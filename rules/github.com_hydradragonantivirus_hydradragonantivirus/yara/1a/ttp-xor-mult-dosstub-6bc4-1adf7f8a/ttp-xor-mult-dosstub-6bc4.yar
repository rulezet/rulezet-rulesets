rule TTP_XOR_MULT_DOSStub_6bc4 {
  strings:
    $key_6bc4 = { 3f ac [2] 4b b4 [2] 0c b6 [2] 4b a7 [2] 05 ab [2] 09 a1 [2] 1e aa [2] 05 e4 [2] 38 }

  condition:
    any of them
}