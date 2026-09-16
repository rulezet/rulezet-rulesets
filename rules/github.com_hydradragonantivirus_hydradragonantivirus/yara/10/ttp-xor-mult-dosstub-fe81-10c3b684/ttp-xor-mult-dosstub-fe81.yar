rule TTP_XOR_MULT_DOSStub_fe81 {
  strings:
    $key_fe81 = { aa e9 [2] de f1 [2] 99 f3 [2] de e2 [2] 90 ee [2] 9c e4 [2] 8b ef [2] 90 a1 [2] ad }

  condition:
    any of them
}