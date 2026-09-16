rule TTP_XOR_MULT_DOSStub_5a81 {
  strings:
    $key_5a81 = { 0e e9 [2] 7a f1 [2] 3d f3 [2] 7a e2 [2] 34 ee [2] 38 e4 [2] 2f ef [2] 34 a1 [2] 09 }

  condition:
    any of them
}