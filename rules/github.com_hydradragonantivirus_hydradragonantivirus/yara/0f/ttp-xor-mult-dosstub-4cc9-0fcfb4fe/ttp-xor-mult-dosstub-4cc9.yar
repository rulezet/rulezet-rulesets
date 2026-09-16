rule TTP_XOR_MULT_DOSStub_4cc9 {
  strings:
    $key_4cc9 = { 18 a1 [2] 6c b9 [2] 2b bb [2] 6c aa [2] 22 a6 [2] 2e ac [2] 39 a7 [2] 22 e9 [2] 1f }

  condition:
    any of them
}