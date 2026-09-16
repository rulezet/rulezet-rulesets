rule TTP_XOR_MULT_DOSStub_7e89 {
  strings:
    $key_7e89 = { 2a e1 [2] 5e f9 [2] 19 fb [2] 5e ea [2] 10 e6 [2] 1c ec [2] 0b e7 [2] 10 a9 [2] 2d }

  condition:
    any of them
}