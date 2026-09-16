rule TTP_XOR_MULT_DOSStub_6cc9 {
  strings:
    $key_6cc9 = { 38 a1 [2] 4c b9 [2] 0b bb [2] 4c aa [2] 02 a6 [2] 0e ac [2] 19 a7 [2] 02 e9 [2] 3f }

  condition:
    any of them
}