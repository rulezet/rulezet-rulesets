rule TTP_XOR_MULT_DOSStub_4d81 {
  strings:
    $key_4d81 = { 19 e9 [2] 6d f1 [2] 2a f3 [2] 6d e2 [2] 23 ee [2] 2f e4 [2] 38 ef [2] 23 a1 [2] 1e }

  condition:
    any of them
}