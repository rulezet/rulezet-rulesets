rule TTP_XOR_MULT_DOSStub_0e86 {
  strings:
    $key_0e86 = { 5a ee [2] 2e f6 [2] 69 f4 [2] 2e e5 [2] 60 e9 [2] 6c e3 [2] 7b e8 [2] 60 a6 [2] 5d }

  condition:
    any of them
}