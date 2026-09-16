rule TTP_XOR_MULT_DOSStub_67c6 {
  strings:
    $key_67c6 = { 33 ae [2] 47 b6 [2] 00 b4 [2] 47 a5 [2] 09 a9 [2] 05 a3 [2] 12 a8 [2] 09 e6 [2] 34 }

  condition:
    any of them
}