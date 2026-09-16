rule TTP_XOR_MULT_DOSStub_70d5 {
  strings:
    $key_70d5 = { 24 bd [2] 50 a5 [2] 17 a7 [2] 50 b6 [2] 1e ba [2] 12 b0 [2] 05 bb [2] 1e f5 [2] 23 }

  condition:
    any of them
}