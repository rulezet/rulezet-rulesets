rule TTP_XOR_MULT_DOSStub_0bd4 {
  strings:
    $key_0bd4 = { 5f bc [2] 2b a4 [2] 6c a6 [2] 2b b7 [2] 65 bb [2] 69 b1 [2] 7e ba [2] 65 f4 [2] 58 }

  condition:
    any of them
}