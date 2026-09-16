rule TTP_XOR_MULT_DOSStub_3cc9 {
  strings:
    $key_3cc9 = { 68 a1 [2] 1c b9 [2] 5b bb [2] 1c aa [2] 52 a6 [2] 5e ac [2] 49 a7 [2] 52 e9 [2] 6f }

  condition:
    any of them
}