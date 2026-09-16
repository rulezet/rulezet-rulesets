rule TTP_XOR_MULT_DOSStub_4cc1 {
  strings:
    $key_4cc1 = { 18 a9 [2] 6c b1 [2] 2b b3 [2] 6c a2 [2] 22 ae [2] 2e a4 [2] 39 af [2] 22 e1 [2] 1f }

  condition:
    any of them
}