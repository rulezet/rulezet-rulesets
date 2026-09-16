rule TTP_XOR_MULT_DOSStub_7bc9 {
  strings:
    $key_7bc9 = { 2f a1 [2] 5b b9 [2] 1c bb [2] 5b aa [2] 15 a6 [2] 19 ac [2] 0e a7 [2] 15 e9 [2] 28 }

  condition:
    any of them
}