rule TTP_XOR_MULT_DOSStub_7f89 {
  strings:
    $key_7f89 = { 2b e1 [2] 5f f9 [2] 18 fb [2] 5f ea [2] 11 e6 [2] 1d ec [2] 0a e7 [2] 11 a9 [2] 2c }

  condition:
    any of them
}