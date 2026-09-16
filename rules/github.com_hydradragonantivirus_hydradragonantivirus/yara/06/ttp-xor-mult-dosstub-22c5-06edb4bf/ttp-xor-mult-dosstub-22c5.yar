rule TTP_XOR_MULT_DOSStub_22c5 {
  strings:
    $key_22c5 = { 76 ad [2] 02 b5 [2] 45 b7 [2] 02 a6 [2] 4c aa [2] 40 a0 [2] 57 ab [2] 4c e5 [2] 71 }

  condition:
    any of them
}