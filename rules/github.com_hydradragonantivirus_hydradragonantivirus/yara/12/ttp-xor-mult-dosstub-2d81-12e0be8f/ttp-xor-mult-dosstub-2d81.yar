rule TTP_XOR_MULT_DOSStub_2d81 {
  strings:
    $key_2d81 = { 79 e9 [2] 0d f1 [2] 4a f3 [2] 0d e2 [2] 43 ee [2] 4f e4 [2] 58 ef [2] 43 a1 [2] 7e }

  condition:
    any of them
}