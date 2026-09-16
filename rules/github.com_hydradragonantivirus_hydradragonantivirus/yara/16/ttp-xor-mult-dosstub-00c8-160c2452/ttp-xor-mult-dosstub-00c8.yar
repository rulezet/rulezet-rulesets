rule TTP_XOR_MULT_DOSStub_00c8 {
  strings:
    $key_00c8 = { 54 a0 [2] 20 b8 [2] 67 ba [2] 20 ab [2] 6e a7 [2] 62 ad [2] 75 a6 [2] 6e e8 [2] 53 }

  condition:
    any of them
}