rule TTP_XOR_MULT_DOSStub_7c81 {
  strings:
    $key_7c81 = { 28 e9 [2] 5c f1 [2] 1b f3 [2] 5c e2 [2] 12 ee [2] 1e e4 [2] 09 ef [2] 12 a1 [2] 2f }

  condition:
    any of them
}