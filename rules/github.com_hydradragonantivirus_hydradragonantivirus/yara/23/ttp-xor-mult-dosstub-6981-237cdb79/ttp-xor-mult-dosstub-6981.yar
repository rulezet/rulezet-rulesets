rule TTP_XOR_MULT_DOSStub_6981 {
  strings:
    $key_6981 = { 3d e9 [2] 49 f1 [2] 0e f3 [2] 49 e2 [2] 07 ee [2] 0b e4 [2] 1c ef [2] 07 a1 [2] 3a }

  condition:
    any of them
}