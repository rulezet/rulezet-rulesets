rule TTP_XOR_MULT_DOSStub_6e89 {
  strings:
    $key_6e89 = { 3a e1 [2] 4e f9 [2] 09 fb [2] 4e ea [2] 00 e6 [2] 0c ec [2] 1b e7 [2] 00 a9 [2] 3d }

  condition:
    any of them
}