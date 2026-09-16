rule TTP_XOR_MULT_DOSStub_e2d5 {
  strings:
    $key_e2d5 = { b6 bd [2] c2 a5 [2] 85 a7 [2] c2 b6 [2] 8c ba [2] 80 b0 [2] 97 bb [2] 8c f5 [2] b1 }

  condition:
    any of them
}