rule TTP_XOR_MULT_DOSStub_2bc9 {
  strings:
    $key_2bc9 = { 7f a1 [2] 0b b9 [2] 4c bb [2] 0b aa [2] 45 a6 [2] 49 ac [2] 5e a7 [2] 45 e9 [2] 78 }

  condition:
    any of them
}