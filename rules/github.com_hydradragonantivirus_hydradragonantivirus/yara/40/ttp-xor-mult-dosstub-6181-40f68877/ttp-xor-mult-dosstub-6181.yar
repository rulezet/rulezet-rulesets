rule TTP_XOR_MULT_DOSStub_6181 {
  strings:
    $key_6181 = { 35 e9 [2] 41 f1 [2] 06 f3 [2] 41 e2 [2] 0f ee [2] 03 e4 [2] 14 ef [2] 0f a1 [2] 32 }

  condition:
    any of them
}