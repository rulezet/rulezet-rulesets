rule TTP_XOR_MULT_DOSStub_35c7 {
  strings:
    $key_35c7 = { 61 af [2] 15 b7 [2] 52 b5 [2] 15 a4 [2] 5b a8 [2] 57 a2 [2] 40 a9 [2] 5b e7 [2] 66 }

  condition:
    any of them
}