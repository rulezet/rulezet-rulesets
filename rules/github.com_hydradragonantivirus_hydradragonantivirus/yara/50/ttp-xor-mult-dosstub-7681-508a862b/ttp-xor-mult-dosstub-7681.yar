rule TTP_XOR_MULT_DOSStub_7681 {
  strings:
    $key_7681 = { 22 e9 [2] 56 f1 [2] 11 f3 [2] 56 e2 [2] 18 ee [2] 14 e4 [2] 03 ef [2] 18 a1 [2] 25 }

  condition:
    any of them
}