rule TTP_XOR_MULT_DOSStub_3bc9 {
  strings:
    $key_3bc9 = { 6f a1 [2] 1b b9 [2] 5c bb [2] 1b aa [2] 55 a6 [2] 59 ac [2] 4e a7 [2] 55 e9 [2] 68 }

  condition:
    any of them
}