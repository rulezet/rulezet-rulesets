rule TTP_XOR_MULT_DOSStub_5387 {
  strings:
    $key_5387 = { 07 ef [2] 73 f7 [2] 34 f5 [2] 73 e4 [2] 3d e8 [2] 31 e2 [2] 26 e9 [2] 3d a7 [2] 00 }

  condition:
    any of them
}