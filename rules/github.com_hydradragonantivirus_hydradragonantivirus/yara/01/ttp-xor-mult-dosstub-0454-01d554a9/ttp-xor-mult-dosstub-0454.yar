rule TTP_XOR_MULT_DOSStub_0454 {
  strings:
    $key_0454 = { 50 3c [2] 24 24 [2] 63 26 [2] 24 37 [2] 6a 3b [2] 66 31 [2] 71 3a [2] 6a 74 [2] 57 }

  condition:
    any of them
}