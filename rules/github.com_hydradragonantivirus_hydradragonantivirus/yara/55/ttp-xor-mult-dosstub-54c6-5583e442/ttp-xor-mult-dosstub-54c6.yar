rule TTP_XOR_MULT_DOSStub_54c6 {
  strings:
    $key_54c6 = { 00 ae [2] 74 b6 [2] 33 b4 [2] 74 a5 [2] 3a a9 [2] 36 a3 [2] 21 a8 [2] 3a e6 [2] 07 }

  condition:
    any of them
}