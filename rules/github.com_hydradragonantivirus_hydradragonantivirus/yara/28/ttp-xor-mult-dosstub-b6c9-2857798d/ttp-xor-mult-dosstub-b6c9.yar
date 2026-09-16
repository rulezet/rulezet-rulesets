rule TTP_XOR_MULT_DOSStub_b6c9 {
  strings:
    $key_b6c9 = { e2 a1 [2] 96 b9 [2] d1 bb [2] 96 aa [2] d8 a6 [2] d4 ac [2] c3 a7 [2] d8 e9 [2] e5 }

  condition:
    any of them
}