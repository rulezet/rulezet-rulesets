rule TTP_XOR_MULT_DOSStub_0449 {
  strings:
    $key_0449 = { 50 21 [2] 24 39 [2] 63 3b [2] 24 2a [2] 6a 26 [2] 66 2c [2] 71 27 [2] 6a 69 [2] 57 }

  condition:
    any of them
}