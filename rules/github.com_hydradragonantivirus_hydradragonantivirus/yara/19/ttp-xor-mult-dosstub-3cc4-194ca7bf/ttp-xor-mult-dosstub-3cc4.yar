rule TTP_XOR_MULT_DOSStub_3cc4 {
  strings:
    $key_3cc4 = { 68 ac [2] 1c b4 [2] 5b b6 [2] 1c a7 [2] 52 ab [2] 5e a1 [2] 49 aa [2] 52 e4 [2] 6f }

  condition:
    any of them
}