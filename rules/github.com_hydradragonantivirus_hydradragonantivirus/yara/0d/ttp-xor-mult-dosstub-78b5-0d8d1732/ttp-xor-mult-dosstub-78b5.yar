rule TTP_XOR_MULT_DOSStub_78b5 {
  strings:
    $key_78b5 = { 2c dd [2] 58 c5 [2] 1f c7 [2] 58 d6 [2] 16 da [2] 1a d0 [2] 0d db [2] 16 95 [2] 2b }

  condition:
    any of them
}