rule TTP_XOR_MULT_DOSStub_4454 {
  strings:
    $key_4454 = { 10 3c [2] 64 24 [2] 23 26 [2] 64 37 [2] 2a 3b [2] 26 31 [2] 31 3a [2] 2a 74 [2] 17 }

  condition:
    any of them
}