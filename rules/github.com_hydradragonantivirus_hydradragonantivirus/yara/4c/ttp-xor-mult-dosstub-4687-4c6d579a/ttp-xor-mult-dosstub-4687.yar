rule TTP_XOR_MULT_DOSStub_4687 {
  strings:
    $key_4687 = { 12 ef [2] 66 f7 [2] 21 f5 [2] 66 e4 [2] 28 e8 [2] 24 e2 [2] 33 e9 [2] 28 a7 [2] 15 }

  condition:
    any of them
}