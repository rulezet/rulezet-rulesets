rule TTP_XOR_MULT_DOSStub_eac9 {
  strings:
    $key_eac9 = { be a1 [2] ca b9 [2] 8d bb [2] ca aa [2] 84 a6 [2] 88 ac [2] 9f a7 [2] 84 e9 [2] b9 }

  condition:
    any of them
}