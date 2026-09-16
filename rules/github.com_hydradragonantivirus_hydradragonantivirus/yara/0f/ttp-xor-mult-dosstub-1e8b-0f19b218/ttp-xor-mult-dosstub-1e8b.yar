rule TTP_XOR_MULT_DOSStub_1e8b {
  strings:
    $key_1e8b = { 4a e3 [2] 3e fb [2] 79 f9 [2] 3e e8 [2] 70 e4 [2] 7c ee [2] 6b e5 [2] 70 ab [2] 4d }

  condition:
    any of them
}