rule TTP_XOR_MULT_DOSStub_7986 {
  strings:
    $key_7986 = { 2d ee [2] 59 f6 [2] 1e f4 [2] 59 e5 [2] 17 e9 [2] 1b e3 [2] 0c e8 [2] 17 a6 [2] 2a }

  condition:
    any of them
}