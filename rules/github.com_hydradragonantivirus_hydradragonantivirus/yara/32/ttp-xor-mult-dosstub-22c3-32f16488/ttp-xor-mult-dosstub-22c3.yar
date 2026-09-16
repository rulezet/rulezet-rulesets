rule TTP_XOR_MULT_DOSStub_22c3 {
  strings:
    $key_22c3 = { 76 ab [2] 02 b3 [2] 45 b1 [2] 02 a0 [2] 4c ac [2] 40 a6 [2] 57 ad [2] 4c e3 [2] 71 }

  condition:
    any of them
}