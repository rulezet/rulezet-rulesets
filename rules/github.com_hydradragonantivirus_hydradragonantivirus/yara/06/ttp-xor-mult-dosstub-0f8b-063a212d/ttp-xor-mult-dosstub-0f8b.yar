rule TTP_XOR_MULT_DOSStub_0f8b {
  strings:
    $key_0f8b = { 5b e3 [2] 2f fb [2] 68 f9 [2] 2f e8 [2] 61 e4 [2] 6d ee [2] 7a e5 [2] 61 ab [2] 5c }

  condition:
    any of them
}