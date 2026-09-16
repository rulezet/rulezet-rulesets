rule TTP_XOR_MULT_DOSStub_46c6 {
  strings:
    $key_46c6 = { 12 ae [2] 66 b6 [2] 21 b4 [2] 66 a5 [2] 28 a9 [2] 24 a3 [2] 33 a8 [2] 28 e6 [2] 15 }

  condition:
    any of them
}