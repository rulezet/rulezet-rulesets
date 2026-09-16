rule TTP_XOR_MULT_DOSStub_1cc9 {
  strings:
    $key_1cc9 = { 48 a1 [2] 3c b9 [2] 7b bb [2] 3c aa [2] 72 a6 [2] 7e ac [2] 69 a7 [2] 72 e9 [2] 4f }

  condition:
    any of them
}