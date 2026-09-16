rule TTP_XOR_MULT_DOSStub_1cc4 {
  strings:
    $key_1cc4 = { 48 ac [2] 3c b4 [2] 7b b6 [2] 3c a7 [2] 72 ab [2] 7e a1 [2] 69 aa [2] 72 e4 [2] 4f }

  condition:
    any of them
}