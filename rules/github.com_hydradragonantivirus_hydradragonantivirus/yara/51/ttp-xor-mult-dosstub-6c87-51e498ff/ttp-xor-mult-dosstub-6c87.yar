rule TTP_XOR_MULT_DOSStub_6c87 {
  strings:
    $key_6c87 = { 38 ef [2] 4c f7 [2] 0b f5 [2] 4c e4 [2] 02 e8 [2] 0e e2 [2] 19 e9 [2] 02 a7 [2] 3f }

  condition:
    any of them
}