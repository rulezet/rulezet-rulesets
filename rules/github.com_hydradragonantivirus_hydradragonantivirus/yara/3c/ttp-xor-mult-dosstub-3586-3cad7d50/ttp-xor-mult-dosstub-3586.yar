rule TTP_XOR_MULT_DOSStub_3586 {
  strings:
    $key_3586 = { 61 ee [2] 15 f6 [2] 52 f4 [2] 15 e5 [2] 5b e9 [2] 57 e3 [2] 40 e8 [2] 5b a6 [2] 66 }

  condition:
    any of them
}