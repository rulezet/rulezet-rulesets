rule TTP_XOR_MULT_DOSStub_1bd4 {
  strings:
    $key_1bd4 = { 4f bc [2] 3b a4 [2] 7c a6 [2] 3b b7 [2] 75 bb [2] 79 b1 [2] 6e ba [2] 75 f4 [2] 48 }

  condition:
    any of them
}