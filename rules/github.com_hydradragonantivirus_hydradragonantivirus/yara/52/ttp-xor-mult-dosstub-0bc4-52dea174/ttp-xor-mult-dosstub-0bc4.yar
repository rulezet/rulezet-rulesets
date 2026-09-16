rule TTP_XOR_MULT_DOSStub_0bc4 {
  strings:
    $key_0bc4 = { 5f ac [2] 2b b4 [2] 6c b6 [2] 2b a7 [2] 65 ab [2] 69 a1 [2] 7e aa [2] 65 e4 [2] 58 }

  condition:
    any of them
}