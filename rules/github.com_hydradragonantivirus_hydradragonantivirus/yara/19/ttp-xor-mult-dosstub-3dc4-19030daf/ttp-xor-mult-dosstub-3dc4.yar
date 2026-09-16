rule TTP_XOR_MULT_DOSStub_3dc4 {
  strings:
    $key_3dc4 = { 69 ac [2] 1d b4 [2] 5a b6 [2] 1d a7 [2] 53 ab [2] 5f a1 [2] 48 aa [2] 53 e4 [2] 6e }

  condition:
    any of them
}