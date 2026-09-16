rule TTP_XOR_MULT_DOSStub_a5d5 {
  strings:
    $key_a5d5 = { f1 bd [2] 85 a5 [2] c2 a7 [2] 85 b6 [2] cb ba [2] c7 b0 [2] d0 bb [2] cb f5 [2] f6 }

  condition:
    any of them
}