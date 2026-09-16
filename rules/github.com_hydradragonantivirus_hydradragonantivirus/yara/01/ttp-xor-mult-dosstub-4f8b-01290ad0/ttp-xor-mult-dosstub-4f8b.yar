rule TTP_XOR_MULT_DOSStub_4f8b {
  strings:
    $key_4f8b = { 1b e3 [2] 6f fb [2] 28 f9 [2] 6f e8 [2] 21 e4 [2] 2d ee [2] 3a e5 [2] 21 ab [2] 1c }

  condition:
    any of them
}