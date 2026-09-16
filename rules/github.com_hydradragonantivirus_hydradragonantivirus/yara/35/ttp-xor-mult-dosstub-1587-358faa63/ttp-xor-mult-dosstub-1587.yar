rule TTP_XOR_MULT_DOSStub_1587 {
  strings:
    $key_1587 = { 41 ef [2] 35 f7 [2] 72 f5 [2] 35 e4 [2] 7b e8 [2] 77 e2 [2] 60 e9 [2] 7b a7 [2] 46 }

  condition:
    any of them
}