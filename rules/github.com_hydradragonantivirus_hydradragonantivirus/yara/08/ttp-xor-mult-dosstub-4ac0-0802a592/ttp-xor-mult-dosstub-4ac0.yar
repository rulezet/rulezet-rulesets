rule TTP_XOR_MULT_DOSStub_4ac0 {
  strings:
    $key_4ac0 = { 1e a8 [2] 6a b0 [2] 2d b2 [2] 6a a3 [2] 24 af [2] 28 a5 [2] 3f ae [2] 24 e0 [2] 19 }

  condition:
    any of them
}