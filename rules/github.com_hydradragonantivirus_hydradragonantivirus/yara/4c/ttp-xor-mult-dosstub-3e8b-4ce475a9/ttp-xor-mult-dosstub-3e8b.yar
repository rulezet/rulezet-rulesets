rule TTP_XOR_MULT_DOSStub_3e8b {
  strings:
    $key_3e8b = { 6a e3 [2] 1e fb [2] 59 f9 [2] 1e e8 [2] 50 e4 [2] 5c ee [2] 4b e5 [2] 50 ab [2] 6d }

  condition:
    any of them
}