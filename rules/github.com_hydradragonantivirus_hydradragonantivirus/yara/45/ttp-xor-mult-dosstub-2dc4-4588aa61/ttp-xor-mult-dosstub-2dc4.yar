rule TTP_XOR_MULT_DOSStub_2dc4 {
  strings:
    $key_2dc4 = { 79 ac [2] 0d b4 [2] 4a b6 [2] 0d a7 [2] 43 ab [2] 4f a1 [2] 58 aa [2] 43 e4 [2] 7e }

  condition:
    any of them
}