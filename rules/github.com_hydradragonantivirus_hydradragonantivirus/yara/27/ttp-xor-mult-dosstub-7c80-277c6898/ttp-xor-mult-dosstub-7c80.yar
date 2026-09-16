rule TTP_XOR_MULT_DOSStub_7c80 {
  strings:
    $key_7c80 = { 28 e8 [2] 5c f0 [2] 1b f2 [2] 5c e3 [2] 12 ef [2] 1e e5 [2] 09 ee [2] 12 a0 [2] 2f }

  condition:
    any of them
}