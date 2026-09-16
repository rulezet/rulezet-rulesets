rule TTP_XOR_MULT_DOSStub_78c8 {
  strings:
    $key_78c8 = { 2c a0 [2] 58 b8 [2] 1f ba [2] 58 ab [2] 16 a7 [2] 1a ad [2] 0d a6 [2] 16 e8 [2] 2b }

  condition:
    any of them
}