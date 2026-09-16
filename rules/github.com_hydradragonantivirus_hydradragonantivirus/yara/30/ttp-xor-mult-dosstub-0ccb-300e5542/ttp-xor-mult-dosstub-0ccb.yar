rule TTP_XOR_MULT_DOSStub_0ccb {
  strings:
    $key_0ccb = { 58 a3 [2] 2c bb [2] 6b b9 [2] 2c a8 [2] 62 a4 [2] 6e ae [2] 79 a5 [2] 62 eb [2] 5f }

  condition:
    any of them
}