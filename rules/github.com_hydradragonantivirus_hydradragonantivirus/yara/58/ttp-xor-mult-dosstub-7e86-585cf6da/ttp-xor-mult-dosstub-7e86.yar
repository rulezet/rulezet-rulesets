rule TTP_XOR_MULT_DOSStub_7e86 {
  strings:
    $key_7e86 = { 2a ee [2] 5e f6 [2] 19 f4 [2] 5e e5 [2] 10 e9 [2] 1c e3 [2] 0b e8 [2] 10 a6 [2] 2d }

  condition:
    any of them
}