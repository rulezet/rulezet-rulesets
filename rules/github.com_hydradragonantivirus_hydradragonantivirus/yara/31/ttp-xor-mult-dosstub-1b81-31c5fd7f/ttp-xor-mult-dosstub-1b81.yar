rule TTP_XOR_MULT_DOSStub_1b81 {
  strings:
    $key_1b81 = { 4f e9 [2] 3b f1 [2] 7c f3 [2] 3b e2 [2] 75 ee [2] 79 e4 [2] 6e ef [2] 75 a1 [2] 48 }

  condition:
    any of them
}