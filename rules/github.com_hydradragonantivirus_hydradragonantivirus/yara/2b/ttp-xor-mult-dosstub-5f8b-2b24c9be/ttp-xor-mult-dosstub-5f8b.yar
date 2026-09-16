rule TTP_XOR_MULT_DOSStub_5f8b {
  strings:
    $key_5f8b = { 0b e3 [2] 7f fb [2] 38 f9 [2] 7f e8 [2] 31 e4 [2] 3d ee [2] 2a e5 [2] 31 ab [2] 0c }

  condition:
    any of them
}