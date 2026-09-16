rule TTP_XOR_MULT_DOSStub_5e86 {
  strings:
    $key_5e86 = { 0a ee [2] 7e f6 [2] 39 f4 [2] 7e e5 [2] 30 e9 [2] 3c e3 [2] 2b e8 [2] 30 a6 [2] 0d }

  condition:
    any of them
}