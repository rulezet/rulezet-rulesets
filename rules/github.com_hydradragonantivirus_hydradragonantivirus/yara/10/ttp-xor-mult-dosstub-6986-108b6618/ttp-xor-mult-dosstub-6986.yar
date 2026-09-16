rule TTP_XOR_MULT_DOSStub_6986 {
  strings:
    $key_6986 = { 3d ee [2] 49 f6 [2] 0e f4 [2] 49 e5 [2] 07 e9 [2] 0b e3 [2] 1c e8 [2] 07 a6 [2] 3a }

  condition:
    any of them
}