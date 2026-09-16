rule TTP_XOR_MULT_DOSStub_1bc4 {
  strings:
    $key_1bc4 = { 4f ac [2] 3b b4 [2] 7c b6 [2] 3b a7 [2] 75 ab [2] 79 a1 [2] 6e aa [2] 75 e4 [2] 48 }

  condition:
    any of them
}