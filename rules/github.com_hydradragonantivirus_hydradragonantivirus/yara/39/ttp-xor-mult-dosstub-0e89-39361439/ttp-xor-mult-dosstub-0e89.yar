rule TTP_XOR_MULT_DOSStub_0e89 {
  strings:
    $key_0e89 = { 5a e1 [2] 2e f9 [2] 69 fb [2] 2e ea [2] 60 e6 [2] 6c ec [2] 7b e7 [2] 60 a9 [2] 5d }

  condition:
    any of them
}