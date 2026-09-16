rule TTP_XOR_MULT_DOSStub_2ac9 {
  strings:
    $key_2ac9 = { 7e a1 [2] 0a b9 [2] 4d bb [2] 0a aa [2] 44 a6 [2] 48 ac [2] 5f a7 [2] 44 e9 [2] 79 }

  condition:
    any of them
}