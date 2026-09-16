rule TTP_XOR_MULT_DOSStub_5681 {
  strings:
    $key_5681 = { 02 e9 [2] 76 f1 [2] 31 f3 [2] 76 e2 [2] 38 ee [2] 34 e4 [2] 23 ef [2] 38 a1 [2] 05 }

  condition:
    any of them
}