rule TTP_XOR_MULT_DOSStub_5e89 {
  strings:
    $key_5e89 = { 0a e1 [2] 7e f9 [2] 39 fb [2] 7e ea [2] 30 e6 [2] 3c ec [2] 2b e7 [2] 30 a9 [2] 0d }

  condition:
    any of them
}