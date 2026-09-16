rule TTP_XOR_MULT_DOSStub_7586 {
  strings:
    $key_7586 = { 21 ee [2] 55 f6 [2] 12 f4 [2] 55 e5 [2] 1b e9 [2] 17 e3 [2] 00 e8 [2] 1b a6 [2] 26 }

  condition:
    any of them
}