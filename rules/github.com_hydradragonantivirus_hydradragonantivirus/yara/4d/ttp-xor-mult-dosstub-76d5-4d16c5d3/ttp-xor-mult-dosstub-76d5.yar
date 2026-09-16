rule TTP_XOR_MULT_DOSStub_76d5 {
  strings:
    $key_76d5 = { 22 bd [2] 56 a5 [2] 11 a7 [2] 56 b6 [2] 18 ba [2] 14 b0 [2] 03 bb [2] 18 f5 [2] 25 }

  condition:
    any of them
}