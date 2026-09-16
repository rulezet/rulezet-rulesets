rule TTP_XOR_MULT_DOSStub_14c7 {
  strings:
    $key_14c7 = { 40 af [2] 34 b7 [2] 73 b5 [2] 34 a4 [2] 7a a8 [2] 76 a2 [2] 61 a9 [2] 7a e7 [2] 47 }

  condition:
    any of them
}