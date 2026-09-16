rule TTP_XOR_MULT_DOSStub_e4d5 {
  strings:
    $key_e4d5 = { b0 bd [2] c4 a5 [2] 83 a7 [2] c4 b6 [2] 8a ba [2] 86 b0 [2] 91 bb [2] 8a f5 [2] b7 }

  condition:
    any of them
}