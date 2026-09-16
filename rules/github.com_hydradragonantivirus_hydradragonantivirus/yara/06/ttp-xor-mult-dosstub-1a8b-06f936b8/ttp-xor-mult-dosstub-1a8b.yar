rule TTP_XOR_MULT_DOSStub_1a8b {
  strings:
    $key_1a8b = { 4e e3 [2] 3a fb [2] 7d f9 [2] 3a e8 [2] 74 e4 [2] 78 ee [2] 6f e5 [2] 74 ab [2] 49 }

  condition:
    any of them
}