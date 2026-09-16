rule TTP_XOR_MULT_DOSStub_4bc9 {
  strings:
    $key_4bc9 = { 1f a1 [2] 6b b9 [2] 2c bb [2] 6b aa [2] 25 a6 [2] 29 ac [2] 3e a7 [2] 25 e9 [2] 18 }

  condition:
    any of them
}