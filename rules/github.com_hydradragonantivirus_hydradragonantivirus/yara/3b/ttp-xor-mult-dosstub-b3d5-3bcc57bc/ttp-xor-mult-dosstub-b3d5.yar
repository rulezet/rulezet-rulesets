rule TTP_XOR_MULT_DOSStub_b3d5 {
  strings:
    $key_b3d5 = { e7 bd [2] 93 a5 [2] d4 a7 [2] 93 b6 [2] dd ba [2] d1 b0 [2] c6 bb [2] dd f5 [2] e0 }

  condition:
    any of them
}