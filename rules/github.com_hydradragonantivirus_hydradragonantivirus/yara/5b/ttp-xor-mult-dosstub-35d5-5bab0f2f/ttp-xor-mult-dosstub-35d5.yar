rule TTP_XOR_MULT_DOSStub_35d5 {
  strings:
    $key_35d5 = { 61 bd [2] 15 a5 [2] 52 a7 [2] 15 b6 [2] 5b ba [2] 57 b0 [2] 40 bb [2] 5b f5 [2] 66 }

  condition:
    any of them
}