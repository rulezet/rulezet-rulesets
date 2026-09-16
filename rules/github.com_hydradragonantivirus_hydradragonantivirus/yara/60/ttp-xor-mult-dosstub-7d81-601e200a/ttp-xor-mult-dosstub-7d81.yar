rule TTP_XOR_MULT_DOSStub_7d81 {
  strings:
    $key_7d81 = { 29 e9 [2] 5d f1 [2] 1a f3 [2] 5d e2 [2] 13 ee [2] 1f e4 [2] 08 ef [2] 13 a1 [2] 2e }

  condition:
    any of them
}