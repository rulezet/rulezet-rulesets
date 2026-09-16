rule TTP_XOR_MULT_DOSStub_0a8b {
  strings:
    $key_0a8b = { 5e e3 [2] 2a fb [2] 6d f9 [2] 2a e8 [2] 64 e4 [2] 68 ee [2] 7f e5 [2] 64 ab [2] 59 }

  condition:
    any of them
}