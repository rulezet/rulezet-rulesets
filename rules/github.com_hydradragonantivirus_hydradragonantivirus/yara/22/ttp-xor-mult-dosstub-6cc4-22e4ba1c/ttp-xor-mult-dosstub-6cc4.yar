rule TTP_XOR_MULT_DOSStub_6cc4 {
  strings:
    $key_6cc4 = { 38 ac [2] 4c b4 [2] 0b b6 [2] 4c a7 [2] 02 ab [2] 0e a1 [2] 19 aa [2] 02 e4 [2] 3f }

  condition:
    any of them
}