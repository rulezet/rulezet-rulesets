rule TTP_XOR_MULT_DOSStub_1096 {
  strings:
    $key_1096 = { 44 fe [2] 30 e6 [2] 77 e4 [2] 30 f5 [2] 7e f9 [2] 72 f3 [2] 65 f8 [2] 7e b6 [2] 43 }

  condition:
    any of them
}