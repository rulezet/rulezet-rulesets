rule TTP_XOR_MULT_DOSStub_5d87 {
  strings:
    $key_5d87 = { 09 ef [2] 7d f7 [2] 3a f5 [2] 7d e4 [2] 33 e8 [2] 3f e2 [2] 28 e9 [2] 33 a7 [2] 0e }

  condition:
    any of them
}