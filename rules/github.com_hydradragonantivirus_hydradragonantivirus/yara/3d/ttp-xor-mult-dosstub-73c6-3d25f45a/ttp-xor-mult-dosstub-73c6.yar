rule TTP_XOR_MULT_DOSStub_73c6 {
  strings:
    $key_73c6 = { 27 ae [2] 53 b6 [2] 14 b4 [2] 53 a5 [2] 1d a9 [2] 11 a3 [2] 06 a8 [2] 1d e6 [2] 20 }

  condition:
    any of them
}