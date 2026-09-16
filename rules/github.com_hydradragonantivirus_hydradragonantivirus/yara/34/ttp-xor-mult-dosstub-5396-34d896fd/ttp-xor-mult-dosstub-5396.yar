rule TTP_XOR_MULT_DOSStub_5396 {
  strings:
    $key_5396 = { 07 fe [2] 73 e6 [2] 34 e4 [2] 73 f5 [2] 3d f9 [2] 31 f3 [2] 26 f8 [2] 3d b6 [2] 00 }

  condition:
    any of them
}