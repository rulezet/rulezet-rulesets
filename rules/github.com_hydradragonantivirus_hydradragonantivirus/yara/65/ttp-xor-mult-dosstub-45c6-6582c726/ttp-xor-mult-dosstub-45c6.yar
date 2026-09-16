rule TTP_XOR_MULT_DOSStub_45c6 {
  strings:
    $key_45c6 = { 11 ae [2] 65 b6 [2] 22 b4 [2] 65 a5 [2] 2b a9 [2] 27 a3 [2] 30 a8 [2] 2b e6 [2] 16 }

  condition:
    any of them
}