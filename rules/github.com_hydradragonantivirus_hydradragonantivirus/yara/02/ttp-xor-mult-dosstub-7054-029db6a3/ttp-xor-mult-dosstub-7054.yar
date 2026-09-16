rule TTP_XOR_MULT_DOSStub_7054 {
  strings:
    $key_7054 = { 24 3c [2] 50 24 [2] 17 26 [2] 50 37 [2] 1e 3b [2] 12 31 [2] 05 3a [2] 1e 74 [2] 23 }

  condition:
    any of them
}