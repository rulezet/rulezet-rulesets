rule TTP_XOR_MULT_DOSStub_6bc9 {
  strings:
    $key_6bc9 = { 3f a1 [2] 4b b9 [2] 0c bb [2] 4b aa [2] 05 a6 [2] 09 ac [2] 1e a7 [2] 05 e9 [2] 38 }

  condition:
    any of them
}