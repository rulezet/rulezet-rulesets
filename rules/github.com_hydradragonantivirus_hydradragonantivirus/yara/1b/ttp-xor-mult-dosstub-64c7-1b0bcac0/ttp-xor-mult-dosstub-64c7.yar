rule TTP_XOR_MULT_DOSStub_64c7 {
  strings:
    $key_64c7 = { 30 af [2] 44 b7 [2] 03 b5 [2] 44 a4 [2] 0a a8 [2] 06 a2 [2] 11 a9 [2] 0a e7 [2] 37 }

  condition:
    any of them
}