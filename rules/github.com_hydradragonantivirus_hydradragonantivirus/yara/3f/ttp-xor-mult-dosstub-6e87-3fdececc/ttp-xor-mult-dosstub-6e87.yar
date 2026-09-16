rule TTP_XOR_MULT_DOSStub_6e87 {
  strings:
    $key_6e87 = { 3a ef [2] 4e f7 [2] 09 f5 [2] 4e e4 [2] 00 e8 [2] 0c e2 [2] 1b e9 [2] 00 a7 [2] 3d }

  condition:
    any of them
}