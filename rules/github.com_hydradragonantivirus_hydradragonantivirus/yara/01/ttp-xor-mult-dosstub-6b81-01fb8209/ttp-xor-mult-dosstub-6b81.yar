rule TTP_XOR_MULT_DOSStub_6b81 {
  strings:
    $key_6b81 = { 3f e9 [2] 4b f1 [2] 0c f3 [2] 4b e2 [2] 05 ee [2] 09 e4 [2] 1e ef [2] 05 a1 [2] 38 }

  condition:
    any of them
}