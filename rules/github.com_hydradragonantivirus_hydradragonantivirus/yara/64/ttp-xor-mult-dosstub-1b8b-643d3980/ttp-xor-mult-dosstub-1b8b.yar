rule TTP_XOR_MULT_DOSStub_1b8b {
  strings:
    $key_1b8b = { 4f e3 [2] 3b fb [2] 7c f9 [2] 3b e8 [2] 75 e4 [2] 79 ee [2] 6e e5 [2] 75 ab [2] 48 }

  condition:
    any of them
}