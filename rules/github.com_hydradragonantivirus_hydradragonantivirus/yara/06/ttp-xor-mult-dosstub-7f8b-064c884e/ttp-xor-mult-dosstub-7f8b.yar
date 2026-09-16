rule TTP_XOR_MULT_DOSStub_7f8b {
  strings:
    $key_7f8b = { 2b e3 [2] 5f fb [2] 18 f9 [2] 5f e8 [2] 11 e4 [2] 1d ee [2] 0a e5 [2] 11 ab [2] 2c }

  condition:
    any of them
}