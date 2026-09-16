rule TTP_XOR_MULT_DOSStub_1ac9 {
  strings:
    $key_1ac9 = { 4e a1 [2] 3a b9 [2] 7d bb [2] 3a aa [2] 74 a6 [2] 78 ac [2] 6f a7 [2] 74 e9 [2] 49 }

  condition:
    any of them
}