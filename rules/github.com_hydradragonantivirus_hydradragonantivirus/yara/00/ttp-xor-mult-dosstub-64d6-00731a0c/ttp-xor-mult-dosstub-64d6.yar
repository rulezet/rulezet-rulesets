rule TTP_XOR_MULT_DOSStub_64d6 {
  strings:
    $key_64d6 = { 30 be [2] 44 a6 [2] 03 a4 [2] 44 b5 [2] 0a b9 [2] 06 b3 [2] 11 b8 [2] 0a f6 [2] 37 }

  condition:
    any of them
}