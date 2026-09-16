rule TTP_XOR_MULT_DOSStub_4587 {
  strings:
    $key_4587 = { 11 ef [2] 65 f7 [2] 22 f5 [2] 65 e4 [2] 2b e8 [2] 27 e2 [2] 30 e9 [2] 2b a7 [2] 16 }

  condition:
    any of them
}