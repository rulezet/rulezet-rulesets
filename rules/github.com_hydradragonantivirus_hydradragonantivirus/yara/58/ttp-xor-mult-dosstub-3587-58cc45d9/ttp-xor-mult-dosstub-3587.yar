rule TTP_XOR_MULT_DOSStub_3587 {
  strings:
    $key_3587 = { 61 ef [2] 15 f7 [2] 52 f5 [2] 15 e4 [2] 5b e8 [2] 57 e2 [2] 40 e9 [2] 5b a7 [2] 66 }

  condition:
    any of them
}