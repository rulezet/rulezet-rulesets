rule TTP_XOR_MULT_DOSStub_1c81 {
  strings:
    $key_1c81 = { 48 e9 [2] 3c f1 [2] 7b f3 [2] 3c e2 [2] 72 ee [2] 7e e4 [2] 69 ef [2] 72 a1 [2] 4f }

  condition:
    any of them
}