rule TTP_XOR_MULT_DOSStub_46c7 {
  strings:
    $key_46c7 = { 12 af [2] 66 b7 [2] 21 b5 [2] 66 a4 [2] 28 a8 [2] 24 a2 [2] 33 a9 [2] 28 e7 [2] 15 }

  condition:
    any of them
}