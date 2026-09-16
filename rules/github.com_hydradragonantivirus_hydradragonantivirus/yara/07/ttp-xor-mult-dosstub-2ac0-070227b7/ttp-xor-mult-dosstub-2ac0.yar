rule TTP_XOR_MULT_DOSStub_2ac0 {
  strings:
    $key_2ac0 = { 7e a8 [2] 0a b0 [2] 4d b2 [2] 0a a3 [2] 44 af [2] 48 a5 [2] 5f ae [2] 44 e0 [2] 79 }

  condition:
    any of them
}