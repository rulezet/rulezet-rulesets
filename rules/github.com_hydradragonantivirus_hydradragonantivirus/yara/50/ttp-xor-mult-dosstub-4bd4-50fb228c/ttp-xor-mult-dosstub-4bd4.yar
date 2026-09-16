rule TTP_XOR_MULT_DOSStub_4bd4 {
  strings:
    $key_4bd4 = { 1f bc [2] 6b a4 [2] 2c a6 [2] 6b b7 [2] 25 bb [2] 29 b1 [2] 3e ba [2] 25 f4 [2] 18 }

  condition:
    any of them
}