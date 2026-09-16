rule TTP_XOR_MULT_DOSStub_6ac9 {
  strings:
    $key_6ac9 = { 3e a1 [2] 4a b9 [2] 0d bb [2] 4a aa [2] 04 a6 [2] 08 ac [2] 1f a7 [2] 04 e9 [2] 39 }

  condition:
    any of them
}