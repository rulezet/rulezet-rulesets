rule TTP_XOR_MULT_DOSStub_0a81 {
  strings:
    $key_0a81 = { 5e e9 [2] 2a f1 [2] 6d f3 [2] 2a e2 [2] 64 ee [2] 68 e4 [2] 7f ef [2] 64 a1 [2] 59 }

  condition:
    any of them
}