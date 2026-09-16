rule TTP_XOR_MULT_DOSStub_5dd5 {
  strings:
    $key_5dd5 = { 09 bd [2] 7d a5 [2] 3a a7 [2] 7d b6 [2] 33 ba [2] 3f b0 [2] 28 bb [2] 33 f5 [2] 0e }

  condition:
    any of them
}