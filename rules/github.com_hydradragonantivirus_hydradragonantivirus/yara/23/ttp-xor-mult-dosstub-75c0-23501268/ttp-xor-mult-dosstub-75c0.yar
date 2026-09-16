rule TTP_XOR_MULT_DOSStub_75c0 {
  strings:
    $key_75c0 = { 21 a8 [2] 55 b0 [2] 12 b2 [2] 55 a3 [2] 1b af [2] 17 a5 [2] 00 ae [2] 1b e0 [2] 26 }

  condition:
    any of them
}