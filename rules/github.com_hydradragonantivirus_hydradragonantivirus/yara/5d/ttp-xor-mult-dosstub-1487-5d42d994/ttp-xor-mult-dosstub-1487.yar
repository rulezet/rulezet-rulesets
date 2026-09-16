rule TTP_XOR_MULT_DOSStub_1487 {
  strings:
    $key_1487 = { 40 ef [2] 34 f7 [2] 73 f5 [2] 34 e4 [2] 7a e8 [2] 76 e2 [2] 61 e9 [2] 7a a7 [2] 47 }

  condition:
    any of them
}