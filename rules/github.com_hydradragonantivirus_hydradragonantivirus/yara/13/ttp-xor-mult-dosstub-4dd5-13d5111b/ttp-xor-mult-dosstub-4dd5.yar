rule TTP_XOR_MULT_DOSStub_4dd5 {
  strings:
    $key_4dd5 = { 19 bd [2] 6d a5 [2] 2a a7 [2] 6d b6 [2] 23 ba [2] 2f b0 [2] 38 bb [2] 23 f5 [2] 1e }

  condition:
    any of them
}