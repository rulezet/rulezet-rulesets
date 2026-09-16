rule TTP_XOR_MULT_DOSStub_2bd4 {
  strings:
    $key_2bd4 = { 7f bc [2] 0b a4 [2] 4c a6 [2] 0b b7 [2] 45 bb [2] 49 b1 [2] 5e ba [2] 45 f4 [2] 78 }

  condition:
    any of them
}