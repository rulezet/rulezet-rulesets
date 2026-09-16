rule TTP_XOR_MULT_DOSStub_6c81 {
  strings:
    $key_6c81 = { 38 e9 [2] 4c f1 [2] 0b f3 [2] 4c e2 [2] 02 ee [2] 0e e4 [2] 19 ef [2] 02 a1 [2] 3f }

  condition:
    any of them
}