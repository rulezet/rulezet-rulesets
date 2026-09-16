rule TTP_XOR_MULT_DOSStub_3ac9 {
  strings:
    $key_3ac9 = { 6e a1 [2] 1a b9 [2] 5d bb [2] 1a aa [2] 54 a6 [2] 58 ac [2] 4f a7 [2] 54 e9 [2] 69 }

  condition:
    any of them
}