rule TTP_XOR_MULT_DOSStub_62d5 {
  strings:
    $key_62d5 = { 36 bd [2] 42 a5 [2] 05 a7 [2] 42 b6 [2] 0c ba [2] 00 b0 [2] 17 bb [2] 0c f5 [2] 31 }

  condition:
    any of them
}