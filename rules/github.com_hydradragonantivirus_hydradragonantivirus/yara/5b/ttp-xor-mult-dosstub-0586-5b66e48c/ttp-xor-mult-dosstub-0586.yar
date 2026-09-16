rule TTP_XOR_MULT_DOSStub_0586 {
  strings:
    $key_0586 = { 51 ee [2] 25 f6 [2] 62 f4 [2] 25 e5 [2] 6b e9 [2] 67 e3 [2] 70 e8 [2] 6b a6 [2] 56 }

  condition:
    any of them
}