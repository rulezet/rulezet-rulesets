rule TTP_XOR_MULT_DOSStub_5ac9 {
  strings:
    $key_5ac9 = { 0e a1 [2] 7a b9 [2] 3d bb [2] 7a aa [2] 34 a6 [2] 38 ac [2] 2f a7 [2] 34 e9 [2] 09 }

  condition:
    any of them
}