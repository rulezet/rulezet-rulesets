rule TTP_XOR_MULT_DOSStub_4487 {
  strings:
    $key_4487 = { 10 ef [2] 64 f7 [2] 23 f5 [2] 64 e4 [2] 2a e8 [2] 26 e2 [2] 31 e9 [2] 2a a7 [2] 17 }

  condition:
    any of them
}