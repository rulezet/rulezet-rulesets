rule TTP_XOR_MULT_DOSStub_06e3 {
  strings:
    $key_06e3 = { 52 8b [2] 26 93 [2] 61 91 [2] 26 80 [2] 68 8c [2] 64 86 [2] 73 8d [2] 68 c3 [2] 55 }

  condition:
    any of them
}