rule TTP_XOR_MULT_DOSStub_2dd5 {
  strings:
    $key_2dd5 = { 79 bd [2] 0d a5 [2] 4a a7 [2] 0d b6 [2] 43 ba [2] 4f b0 [2] 58 bb [2] 43 f5 [2] 7e }

  condition:
    any of them
}