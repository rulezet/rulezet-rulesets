rule TTP_XOR_MULT_DOSStub_2d87 {
  strings:
    $key_2d87 = { 79 ef [2] 0d f7 [2] 4a f5 [2] 0d e4 [2] 43 e8 [2] 4f e2 [2] 58 e9 [2] 43 a7 [2] 7e }

  condition:
    any of them
}