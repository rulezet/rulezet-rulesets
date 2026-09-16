rule TTP_XOR_MULT_DOSStub_4b81 {
  strings:
    $key_4b81 = { 1f e9 [2] 6b f1 [2] 2c f3 [2] 6b e2 [2] 25 ee [2] 29 e4 [2] 3e ef [2] 25 a1 [2] 18 }

  condition:
    any of them
}