rule TTP_XOR_MULT_DOSStub_7b81 {
  strings:
    $key_7b81 = { 2f e9 [2] 5b f1 [2] 1c f3 [2] 5b e2 [2] 15 ee [2] 19 e4 [2] 0e ef [2] 15 a1 [2] 28 }

  condition:
    any of them
}