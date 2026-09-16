rule TTP_XOR_MULT_DOSStub_7b8b {
  strings:
    $key_7b8b = { 2f e3 [2] 5b fb [2] 1c f9 [2] 5b e8 [2] 15 e4 [2] 19 ee [2] 0e e5 [2] 15 ab [2] 28 }

  condition:
    any of them
}