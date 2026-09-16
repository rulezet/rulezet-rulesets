rule TTP_XOR_MULT_DOSStub_e5c9 {
  strings:
    $key_e5c9 = { b1 a1 [2] c5 b9 [2] 82 bb [2] c5 aa [2] 8b a6 [2] 87 ac [2] 90 a7 [2] 8b e9 [2] b6 }

  condition:
    any of them
}