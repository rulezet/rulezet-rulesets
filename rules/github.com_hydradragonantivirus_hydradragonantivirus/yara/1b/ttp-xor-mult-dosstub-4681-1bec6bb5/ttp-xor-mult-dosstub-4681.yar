rule TTP_XOR_MULT_DOSStub_4681 {
  strings:
    $key_4681 = { 12 e9 [2] 66 f1 [2] 21 f3 [2] 66 e2 [2] 28 ee [2] 24 e4 [2] 33 ef [2] 28 a1 [2] 15 }

  condition:
    any of them
}