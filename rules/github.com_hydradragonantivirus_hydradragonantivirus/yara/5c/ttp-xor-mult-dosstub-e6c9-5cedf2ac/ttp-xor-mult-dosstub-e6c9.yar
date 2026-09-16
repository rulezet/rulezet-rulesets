rule TTP_XOR_MULT_DOSStub_e6c9 {
  strings:
    $key_e6c9 = { b2 a1 [2] c6 b9 [2] 81 bb [2] c6 aa [2] 88 a6 [2] 84 ac [2] 93 a7 [2] 88 e9 [2] b5 }

  condition:
    any of them
}