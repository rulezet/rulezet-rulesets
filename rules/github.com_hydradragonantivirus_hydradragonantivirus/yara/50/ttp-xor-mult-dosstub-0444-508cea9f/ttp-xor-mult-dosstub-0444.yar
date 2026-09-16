rule TTP_XOR_MULT_DOSStub_0444 {
  strings:
    $key_0444 = { 50 2c [2] 24 34 [2] 63 36 [2] 24 27 [2] 6a 2b [2] 66 21 [2] 71 2a [2] 6a 64 [2] 57 }

  condition:
    any of them
}