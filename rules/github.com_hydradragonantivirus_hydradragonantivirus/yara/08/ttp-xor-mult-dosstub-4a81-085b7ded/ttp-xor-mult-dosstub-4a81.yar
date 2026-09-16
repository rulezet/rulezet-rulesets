rule TTP_XOR_MULT_DOSStub_4a81 {
  strings:
    $key_4a81 = { 1e e9 [2] 6a f1 [2] 2d f3 [2] 6a e2 [2] 24 ee [2] 28 e4 [2] 3f ef [2] 24 a1 [2] 19 }

  condition:
    any of them
}