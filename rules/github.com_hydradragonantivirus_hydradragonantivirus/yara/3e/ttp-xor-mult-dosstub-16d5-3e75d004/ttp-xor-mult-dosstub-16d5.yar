rule TTP_XOR_MULT_DOSStub_16d5 {
  strings:
    $key_16d5 = { 42 bd [2] 36 a5 [2] 71 a7 [2] 36 b6 [2] 78 ba [2] 74 b0 [2] 63 bb [2] 78 f5 [2] 45 }

  condition:
    any of them
}