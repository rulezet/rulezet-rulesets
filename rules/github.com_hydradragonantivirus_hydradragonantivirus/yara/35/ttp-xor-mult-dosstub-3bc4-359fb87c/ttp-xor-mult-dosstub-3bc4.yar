rule TTP_XOR_MULT_DOSStub_3bc4 {
  strings:
    $key_3bc4 = { 6f ac [2] 1b b4 [2] 5c b6 [2] 1b a7 [2] 55 ab [2] 59 a1 [2] 4e aa [2] 55 e4 [2] 68 }

  condition:
    any of them
}