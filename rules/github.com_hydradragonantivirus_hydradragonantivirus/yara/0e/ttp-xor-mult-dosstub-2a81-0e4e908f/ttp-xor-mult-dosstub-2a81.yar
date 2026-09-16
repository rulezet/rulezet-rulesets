rule TTP_XOR_MULT_DOSStub_2a81 {
  strings:
    $key_2a81 = { 7e e9 [2] 0a f1 [2] 4d f3 [2] 0a e2 [2] 44 ee [2] 48 e4 [2] 5f ef [2] 44 a1 [2] 79 }

  condition:
    any of them
}