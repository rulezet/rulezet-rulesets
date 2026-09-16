rule TTP_XOR_MULT_DOSStub_73d6 {
  strings:
    $key_73d6 = { 27 be [2] 53 a6 [2] 14 a4 [2] 53 b5 [2] 1d b9 [2] 11 b3 [2] 06 b8 [2] 1d f6 [2] 20 }

  condition:
    any of them
}