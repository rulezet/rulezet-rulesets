rule TTP_XOR_MULT_DOSStub_01e3 {
  strings:
    $key_01e3 = { 55 8b [2] 21 93 [2] 66 91 [2] 21 80 [2] 6f 8c [2] 63 86 [2] 74 8d [2] 6f c3 [2] 52 }

  condition:
    any of them
}