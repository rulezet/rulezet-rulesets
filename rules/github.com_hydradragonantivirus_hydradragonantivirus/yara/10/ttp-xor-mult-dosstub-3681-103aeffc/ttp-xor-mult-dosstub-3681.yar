rule TTP_XOR_MULT_DOSStub_3681 {
  strings:
    $key_3681 = { 62 e9 [2] 16 f1 [2] 51 f3 [2] 16 e2 [2] 58 ee [2] 54 e4 [2] 43 ef [2] 58 a1 [2] 65 }

  condition:
    any of them
}