rule TTP_XOR_MULT_DOSStub_4c81 {
  strings:
    $key_4c81 = { 18 e9 [2] 6c f1 [2] 2b f3 [2] 6c e2 [2] 22 ee [2] 2e e4 [2] 39 ef [2] 22 a1 [2] 1f }

  condition:
    any of them
}