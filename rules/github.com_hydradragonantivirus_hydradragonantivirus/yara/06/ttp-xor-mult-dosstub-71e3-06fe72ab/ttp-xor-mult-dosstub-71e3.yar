rule TTP_XOR_MULT_DOSStub_71e3 {
  strings:
    $key_71e3 = { 25 8b [2] 51 93 [2] 16 91 [2] 51 80 [2] 1f 8c [2] 13 86 [2] 04 8d [2] 1f c3 [2] 22 }

  condition:
    any of them
}