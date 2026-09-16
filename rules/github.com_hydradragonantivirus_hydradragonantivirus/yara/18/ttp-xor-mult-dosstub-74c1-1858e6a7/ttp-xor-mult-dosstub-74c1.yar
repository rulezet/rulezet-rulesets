rule TTP_XOR_MULT_DOSStub_74c1 {
  strings:
    $key_74c1 = { 20 a9 [2] 54 b1 [2] 13 b3 [2] 54 a2 [2] 1a ae [2] 16 a4 [2] 01 af [2] 1a e1 [2] 27 }

  condition:
    any of them
}