rule TTP_XOR_MULT_DOSStub_3cc1 {
  strings:
    $key_3cc1 = { 68 a9 [2] 1c b1 [2] 5b b3 [2] 1c a2 [2] 52 ae [2] 5e a4 [2] 49 af [2] 52 e1 [2] 6f }

  condition:
    any of them
}