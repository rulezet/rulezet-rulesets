rule TTP_XOR_MULT_DOSStub_5b81 {
  strings:
    $key_5b81 = { 0f e9 [2] 7b f1 [2] 3c f3 [2] 7b e2 [2] 35 ee [2] 39 e4 [2] 2e ef [2] 35 a1 [2] 08 }

  condition:
    any of them
}