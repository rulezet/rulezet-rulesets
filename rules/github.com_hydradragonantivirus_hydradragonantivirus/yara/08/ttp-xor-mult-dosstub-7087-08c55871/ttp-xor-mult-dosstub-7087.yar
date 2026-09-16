rule TTP_XOR_MULT_DOSStub_7087 {
  strings:
    $key_7087 = { 24 ef [2] 50 f7 [2] 17 f5 [2] 50 e4 [2] 1e e8 [2] 12 e2 [2] 05 e9 [2] 1e a7 [2] 23 }

  condition:
    any of them
}