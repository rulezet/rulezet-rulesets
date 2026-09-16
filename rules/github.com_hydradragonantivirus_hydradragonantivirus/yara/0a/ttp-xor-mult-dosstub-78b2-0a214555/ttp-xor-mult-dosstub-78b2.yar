rule TTP_XOR_MULT_DOSStub_78b2 {
  strings:
    $key_78b2 = { 2c da [2] 58 c2 [2] 1f c0 [2] 58 d1 [2] 16 dd [2] 1a d7 [2] 0d dc [2] 16 92 [2] 2b }

  condition:
    any of them
}