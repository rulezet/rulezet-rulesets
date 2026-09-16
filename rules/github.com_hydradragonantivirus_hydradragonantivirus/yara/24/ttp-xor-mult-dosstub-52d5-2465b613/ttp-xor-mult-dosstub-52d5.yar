rule TTP_XOR_MULT_DOSStub_52d5 {
  strings:
    $key_52d5 = { 06 bd [2] 72 a5 [2] 35 a7 [2] 72 b6 [2] 3c ba [2] 30 b0 [2] 27 bb [2] 3c f5 [2] 01 }

  condition:
    any of them
}