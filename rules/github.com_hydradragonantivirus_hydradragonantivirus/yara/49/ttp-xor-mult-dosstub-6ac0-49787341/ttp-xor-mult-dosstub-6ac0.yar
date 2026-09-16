rule TTP_XOR_MULT_DOSStub_6ac0 {
  strings:
    $key_6ac0 = { 3e a8 [2] 4a b0 [2] 0d b2 [2] 4a a3 [2] 04 af [2] 08 a5 [2] 1f ae [2] 04 e0 [2] 39 }

  condition:
    any of them
}