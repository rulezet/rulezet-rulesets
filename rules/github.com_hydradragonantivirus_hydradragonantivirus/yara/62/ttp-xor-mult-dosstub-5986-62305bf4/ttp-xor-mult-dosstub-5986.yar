rule TTP_XOR_MULT_DOSStub_5986 {
  strings:
    $key_5986 = { 0d ee [2] 79 f6 [2] 3e f4 [2] 79 e5 [2] 37 e9 [2] 3b e3 [2] 2c e8 [2] 37 a6 [2] 0a }

  condition:
    any of them
}