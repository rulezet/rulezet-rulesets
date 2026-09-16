rule TTP_XOR_MULT_DOSStub_fe87 {
  strings:
    $key_fe87 = { aa ef [2] de f7 [2] 99 f5 [2] de e4 [2] 90 e8 [2] 9c e2 [2] 8b e9 [2] 90 a7 [2] ad }

  condition:
    any of them
}