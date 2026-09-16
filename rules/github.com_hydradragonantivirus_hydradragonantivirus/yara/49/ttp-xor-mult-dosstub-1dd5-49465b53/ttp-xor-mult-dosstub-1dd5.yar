rule TTP_XOR_MULT_DOSStub_1dd5 {
  strings:
    $key_1dd5 = { 49 bd [2] 3d a5 [2] 7a a7 [2] 3d b6 [2] 73 ba [2] 7f b0 [2] 68 bb [2] 73 f5 [2] 4e }

  condition:
    any of them
}