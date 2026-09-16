rule TTP_XOR_MULT_DOSStub_5587 {
  strings:
    $key_5587 = { 01 ef [2] 75 f7 [2] 32 f5 [2] 75 e4 [2] 3b e8 [2] 37 e2 [2] 20 e9 [2] 3b a7 [2] 06 }

  condition:
    any of them
}