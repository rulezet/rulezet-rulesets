rule TTP_XOR_MULT_DOSStub_3e89 {
  strings:
    $key_3e89 = { 6a e1 [2] 1e f9 [2] 59 fb [2] 1e ea [2] 50 e6 [2] 5c ec [2] 4b e7 [2] 50 a9 [2] 6d }

  condition:
    any of them
}