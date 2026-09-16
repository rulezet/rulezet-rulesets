rule TTP_XOR_MULT_DOSStub_0b8b {
  strings:
    $key_0b8b = { 5f e3 [2] 2b fb [2] 6c f9 [2] 2b e8 [2] 65 e4 [2] 69 ee [2] 7e e5 [2] 65 ab [2] 58 }

  condition:
    any of them
}