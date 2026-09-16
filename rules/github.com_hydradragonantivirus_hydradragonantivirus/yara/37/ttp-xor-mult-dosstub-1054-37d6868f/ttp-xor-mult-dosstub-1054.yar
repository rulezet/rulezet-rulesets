rule TTP_XOR_MULT_DOSStub_1054 {
  strings:
    $key_1054 = { 44 3c [2] 30 24 [2] 77 26 [2] 30 37 [2] 7e 3b [2] 72 31 [2] 65 3a [2] 7e 74 [2] 43 }

  condition:
    any of them
}