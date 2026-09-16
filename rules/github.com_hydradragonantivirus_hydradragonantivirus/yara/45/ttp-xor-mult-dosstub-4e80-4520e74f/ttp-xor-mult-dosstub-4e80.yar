rule TTP_XOR_MULT_DOSStub_4e80 {
  strings:
    $key_4e80 = { 1a e8 [2] 6e f0 [2] 29 f2 [2] 6e e3 [2] 20 ef [2] 2c e5 [2] 3b ee [2] 20 a0 [2] 1d }

  condition:
    any of them
}