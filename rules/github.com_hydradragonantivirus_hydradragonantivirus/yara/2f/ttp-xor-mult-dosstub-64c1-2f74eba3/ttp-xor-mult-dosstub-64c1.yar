rule TTP_XOR_MULT_DOSStub_64c1 {
  strings:
    $key_64c1 = { 30 a9 [2] 44 b1 [2] 03 b3 [2] 44 a2 [2] 0a ae [2] 06 a4 [2] 11 af [2] 0a e1 [2] 37 }

  condition:
    any of them
}