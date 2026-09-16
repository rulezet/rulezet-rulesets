rule TTP_XOR_MULT_DOSStub_54d5 {
  strings:
    $key_54d5 = { 00 bd [2] 74 a5 [2] 33 a7 [2] 74 b6 [2] 3a ba [2] 36 b0 [2] 21 bb [2] 3a f5 [2] 07 }

  condition:
    any of them
}