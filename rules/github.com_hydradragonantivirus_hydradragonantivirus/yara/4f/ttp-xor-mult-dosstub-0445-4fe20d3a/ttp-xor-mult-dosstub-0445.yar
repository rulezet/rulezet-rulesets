rule TTP_XOR_MULT_DOSStub_0445 {
  strings:
    $key_0445 = { 50 2d [2] 24 35 [2] 63 37 [2] 24 26 [2] 6a 2a [2] 66 20 [2] 71 2b [2] 6a 65 [2] 57 }

  condition:
    any of them
}