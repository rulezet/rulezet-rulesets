rule TTP_XOR_MULT_DOSStub_6e86 {
  strings:
    $key_6e86 = { 3a ee [2] 4e f6 [2] 09 f4 [2] 4e e5 [2] 00 e9 [2] 0c e3 [2] 1b e8 [2] 00 a6 [2] 3d }

  condition:
    any of them
}