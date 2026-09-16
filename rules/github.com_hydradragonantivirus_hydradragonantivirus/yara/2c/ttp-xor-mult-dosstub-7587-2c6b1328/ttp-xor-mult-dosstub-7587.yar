rule TTP_XOR_MULT_DOSStub_7587 {
  strings:
    $key_7587 = { 21 ef [2] 55 f7 [2] 12 f5 [2] 55 e4 [2] 1b e8 [2] 17 e2 [2] 00 e9 [2] 1b a7 [2] 26 }

  condition:
    any of them
}