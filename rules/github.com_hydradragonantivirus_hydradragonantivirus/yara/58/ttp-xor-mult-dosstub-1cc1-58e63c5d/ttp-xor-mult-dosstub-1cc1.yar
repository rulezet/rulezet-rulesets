rule TTP_XOR_MULT_DOSStub_1cc1 {
  strings:
    $key_1cc1 = { 48 a9 [2] 3c b1 [2] 7b b3 [2] 3c a2 [2] 72 ae [2] 7e a4 [2] 69 af [2] 72 e1 [2] 4f }

  condition:
    any of them
}