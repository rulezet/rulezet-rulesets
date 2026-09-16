rule TTP_XOR_MULT_DOSStub_77d5 {
  strings:
    $key_77d5 = { 23 bd [2] 57 a5 [2] 10 a7 [2] 57 b6 [2] 19 ba [2] 15 b0 [2] 02 bb [2] 19 f5 [2] 24 }

  condition:
    any of them
}