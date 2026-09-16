rule TTP_XOR_MULT_DOSStub_e7d5 {
  strings:
    $key_e7d5 = { b3 bd [2] c7 a5 [2] 80 a7 [2] c7 b6 [2] 89 ba [2] 85 b0 [2] 92 bb [2] 89 f5 [2] b4 }

  condition:
    any of them
}