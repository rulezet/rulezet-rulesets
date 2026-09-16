rule TTP_XOR_MULT_DOSStub_5b8b {
  strings:
    $key_5b8b = { 0f e3 [2] 7b fb [2] 3c f9 [2] 7b e8 [2] 35 e4 [2] 39 ee [2] 2e e5 [2] 35 ab [2] 08 }

  condition:
    any of them
}