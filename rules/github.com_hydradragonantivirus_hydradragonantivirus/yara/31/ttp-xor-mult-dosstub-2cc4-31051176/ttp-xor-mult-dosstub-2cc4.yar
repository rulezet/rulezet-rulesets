rule TTP_XOR_MULT_DOSStub_2cc4 {
  strings:
    $key_2cc4 = { 78 ac [2] 0c b4 [2] 4b b6 [2] 0c a7 [2] 42 ab [2] 4e a1 [2] 59 aa [2] 42 e4 [2] 7f }

  condition:
    any of them
}