rule TTP_XOR_MULT_DOSStub_b3c4 {
  strings:
    $key_b3c4 = { e7 ac [2] 93 b4 [2] d4 b6 [2] 93 a7 [2] dd ab [2] d1 a1 [2] c6 aa [2] dd e4 [2] e0 }

  condition:
    any of them
}