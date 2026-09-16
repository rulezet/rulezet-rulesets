rule TTP_XOR_MULT_DOSStub_6980 {
  strings:
    $key_6980 = { 3d e8 [2] 49 f0 [2] 0e f2 [2] 49 e3 [2] 07 ef [2] 0b e5 [2] 1c ee [2] 07 a0 [2] 3a }

  condition:
    any of them
}