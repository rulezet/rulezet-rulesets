rule TTP_XOR_MULT_DOSStub_04d5 {
  strings:
    $key_04d5 = { 50 bd [2] 24 a5 [2] 63 a7 [2] 24 b6 [2] 6a ba [2] 66 b0 [2] 71 bb [2] 6a f5 [2] 57 }

  condition:
    any of them
}