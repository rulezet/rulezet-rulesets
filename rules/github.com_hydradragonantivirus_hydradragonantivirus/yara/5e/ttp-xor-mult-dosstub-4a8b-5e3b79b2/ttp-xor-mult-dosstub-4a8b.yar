rule TTP_XOR_MULT_DOSStub_4a8b {
  strings:
    $key_4a8b = { 1e e3 [2] 6a fb [2] 2d f9 [2] 6a e8 [2] 24 e4 [2] 28 ee [2] 3f e5 [2] 24 ab [2] 19 }

  condition:
    any of them
}