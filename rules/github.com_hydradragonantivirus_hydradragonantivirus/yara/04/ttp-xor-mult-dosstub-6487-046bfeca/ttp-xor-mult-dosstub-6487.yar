rule TTP_XOR_MULT_DOSStub_6487 {
  strings:
    $key_6487 = { 30 ef [2] 44 f7 [2] 03 f5 [2] 44 e4 [2] 0a e8 [2] 06 e2 [2] 11 e9 [2] 0a a7 [2] 37 }

  condition:
    any of them
}