rule TTP_XOR_MULT_DOSStub_4781 {
  strings:
    $key_4781 = { 13 e9 [2] 67 f1 [2] 20 f3 [2] 67 e2 [2] 29 ee [2] 25 e4 [2] 32 ef [2] 29 a1 [2] 14 }

  condition:
    any of them
}