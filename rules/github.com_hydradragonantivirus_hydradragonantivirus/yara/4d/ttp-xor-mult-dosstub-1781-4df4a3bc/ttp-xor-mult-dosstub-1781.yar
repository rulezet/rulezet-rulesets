rule TTP_XOR_MULT_DOSStub_1781 {
  strings:
    $key_1781 = { 43 e9 [2] 37 f1 [2] 70 f3 [2] 37 e2 [2] 79 ee [2] 75 e4 [2] 62 ef [2] 79 a1 [2] 44 }

  condition:
    any of them
}