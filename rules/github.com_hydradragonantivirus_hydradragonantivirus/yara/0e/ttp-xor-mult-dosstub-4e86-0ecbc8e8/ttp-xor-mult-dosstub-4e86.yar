rule TTP_XOR_MULT_DOSStub_4e86 {
  strings:
    $key_4e86 = { 1a ee [2] 6e f6 [2] 29 f4 [2] 6e e5 [2] 20 e9 [2] 2c e3 [2] 3b e8 [2] 20 a6 [2] 1d }

  condition:
    any of them
}