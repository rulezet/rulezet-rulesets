rule TTP_XOR_MULT_DOSStub_3a87 {
  strings:
    $key_3a87 = { 6e ef [2] 1a f7 [2] 5d f5 [2] 1a e4 [2] 54 e8 [2] 58 e2 [2] 4f e9 [2] 54 a7 [2] 69 }

  condition:
    any of them
}