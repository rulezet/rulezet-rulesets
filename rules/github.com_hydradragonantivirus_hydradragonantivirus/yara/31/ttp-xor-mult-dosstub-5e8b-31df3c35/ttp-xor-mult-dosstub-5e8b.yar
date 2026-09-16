rule TTP_XOR_MULT_DOSStub_5e8b {
  strings:
    $key_5e8b = { 0a e3 [2] 7e fb [2] 39 f9 [2] 7e e8 [2] 30 e4 [2] 3c ee [2] 2b e5 [2] 30 ab [2] 0d }

  condition:
    any of them
}