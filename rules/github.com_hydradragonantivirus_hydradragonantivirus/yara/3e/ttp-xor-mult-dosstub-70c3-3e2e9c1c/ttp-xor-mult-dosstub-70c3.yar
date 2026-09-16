rule TTP_XOR_MULT_DOSStub_70c3 {
  strings:
    $key_70c3 = { 24 ab [2] 50 b3 [2] 17 b1 [2] 50 a0 [2] 1e ac [2] 12 a6 [2] 05 ad [2] 1e e3 [2] 23 }

  condition:
    any of them
}