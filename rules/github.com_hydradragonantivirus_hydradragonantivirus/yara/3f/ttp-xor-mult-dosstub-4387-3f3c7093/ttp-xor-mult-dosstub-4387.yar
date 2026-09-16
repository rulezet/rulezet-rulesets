rule TTP_XOR_MULT_DOSStub_4387 {
  strings:
    $key_4387 = { 17 ef [2] 63 f7 [2] 24 f5 [2] 63 e4 [2] 2d e8 [2] 21 e2 [2] 36 e9 [2] 2d a7 [2] 10 }

  condition:
    any of them
}