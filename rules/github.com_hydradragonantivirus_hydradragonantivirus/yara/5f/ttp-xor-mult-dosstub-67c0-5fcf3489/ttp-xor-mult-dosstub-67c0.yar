rule TTP_XOR_MULT_DOSStub_67c0 {
  strings:
    $key_67c0 = { 33 a8 [2] 47 b0 [2] 00 b2 [2] 47 a3 [2] 09 af [2] 05 a5 [2] 12 ae [2] 09 e0 [2] 34 }

  condition:
    any of them
}