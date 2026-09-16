rule TTP_XOR_MULT_DOSStub_05d5 {
  strings:
    $key_05d5 = { 51 bd [2] 25 a5 [2] 62 a7 [2] 25 b6 [2] 6b ba [2] 67 b0 [2] 70 bb [2] 6b f5 [2] 56 }

  condition:
    any of them
}