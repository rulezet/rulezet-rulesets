rule TTP_XOR_MULT_DOSStub_70c8 {
  strings:
    $key_70c8 = { 24 a0 [2] 50 b8 [2] 17 ba [2] 50 ab [2] 1e a7 [2] 12 ad [2] 05 a6 [2] 1e e8 [2] 23 }

  condition:
    any of them
}