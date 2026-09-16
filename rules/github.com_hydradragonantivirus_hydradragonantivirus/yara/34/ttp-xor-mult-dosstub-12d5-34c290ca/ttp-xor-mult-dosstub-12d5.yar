rule TTP_XOR_MULT_DOSStub_12d5 {
  strings:
    $key_12d5 = { 46 bd [2] 32 a5 [2] 75 a7 [2] 32 b6 [2] 7c ba [2] 70 b0 [2] 67 bb [2] 7c f5 [2] 41 }

  condition:
    any of them
}