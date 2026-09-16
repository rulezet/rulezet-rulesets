rule TTP_XOR_MULT_DOSStub_75c3 {
  strings:
    $key_75c3 = { 21 ab [2] 55 b3 [2] 12 b1 [2] 55 a0 [2] 1b ac [2] 17 a6 [2] 00 ad [2] 1b e3 [2] 26 }

  condition:
    any of them
}