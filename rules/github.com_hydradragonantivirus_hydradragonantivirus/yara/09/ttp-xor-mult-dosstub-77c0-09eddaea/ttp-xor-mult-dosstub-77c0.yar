rule TTP_XOR_MULT_DOSStub_77c0 {
  strings:
    $key_77c0 = { 23 a8 [2] 57 b0 [2] 10 b2 [2] 57 a3 [2] 19 af [2] 15 a5 [2] 02 ae [2] 19 e0 [2] 24 }

  condition:
    any of them
}