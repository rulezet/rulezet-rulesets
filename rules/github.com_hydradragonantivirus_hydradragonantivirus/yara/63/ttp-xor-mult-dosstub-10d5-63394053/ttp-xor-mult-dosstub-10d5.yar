rule TTP_XOR_MULT_DOSStub_10d5 {
  strings:
    $key_10d5 = { 44 bd [2] 30 a5 [2] 77 a7 [2] 30 b6 [2] 7e ba [2] 72 b0 [2] 65 bb [2] 7e f5 [2] 43 }

  condition:
    any of them
}