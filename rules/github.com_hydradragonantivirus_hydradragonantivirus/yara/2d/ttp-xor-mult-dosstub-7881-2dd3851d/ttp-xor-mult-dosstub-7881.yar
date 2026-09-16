rule TTP_XOR_MULT_DOSStub_7881 {
  strings:
    $key_7881 = { 2c e9 [2] 58 f1 [2] 1f f3 [2] 58 e2 [2] 16 ee [2] 1a e4 [2] 0d ef [2] 16 a1 [2] 2b }

  condition:
    any of them
}