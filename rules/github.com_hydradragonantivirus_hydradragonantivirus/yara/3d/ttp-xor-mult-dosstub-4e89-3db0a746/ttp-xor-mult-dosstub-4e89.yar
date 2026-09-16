rule TTP_XOR_MULT_DOSStub_4e89 {
  strings:
    $key_4e89 = { 1a e1 [2] 6e f9 [2] 29 fb [2] 6e ea [2] 20 e6 [2] 2c ec [2] 3b e7 [2] 20 a9 [2] 1d }

  condition:
    any of them
}