rule TTP_XOR_MULT_DOSStub_7e8b {
  strings:
    $key_7e8b = { 2a e3 [2] 5e fb [2] 19 f9 [2] 5e e8 [2] 10 e4 [2] 1c ee [2] 0b e5 [2] 10 ab [2] 2d }

  condition:
    any of them
}