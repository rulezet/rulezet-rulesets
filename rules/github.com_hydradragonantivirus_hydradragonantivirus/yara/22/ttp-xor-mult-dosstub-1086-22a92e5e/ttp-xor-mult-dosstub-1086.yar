rule TTP_XOR_MULT_DOSStub_1086 {
  strings:
    $key_1086 = { 44 ee [2] 30 f6 [2] 77 f4 [2] 30 e5 [2] 7e e9 [2] 72 e3 [2] 65 e8 [2] 7e a6 [2] 43 }

  condition:
    any of them
}