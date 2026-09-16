rule TTP_XOR_MULT_DOSStub_0b81 {
  strings:
    $key_0b81 = { 5f e9 [2] 2b f1 [2] 6c f3 [2] 2b e2 [2] 65 ee [2] 69 e4 [2] 7e ef [2] 65 a1 [2] 58 }

  condition:
    any of them
}