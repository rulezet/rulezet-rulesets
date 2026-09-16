rule TTP_XOR_MULT_DOSStub_dac9 {
  strings:
    $key_dac9 = { 8e a1 [2] fa b9 [2] bd bb [2] fa aa [2] b4 a6 [2] b8 ac [2] af a7 [2] b4 e9 [2] 89 }

  condition:
    any of them
}