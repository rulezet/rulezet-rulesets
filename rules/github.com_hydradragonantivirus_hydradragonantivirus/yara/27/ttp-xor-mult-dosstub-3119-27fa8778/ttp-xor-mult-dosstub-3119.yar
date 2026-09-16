rule TTP_XOR_MULT_DOSStub_3119 {
  strings:
    $key_3119 = { 65 71 [2] 11 69 [2] 56 6b [2] 11 7a [2] 5f 76 [2] 53 7c [2] 44 77 [2] 5f 39 [2] 62 }

  condition:
    any of them
}