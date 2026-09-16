rule TTP_XOR_MULT_DOSStub_158b {
  strings:
    $key_158b = { 41 e3 [2] 35 fb [2] 72 f9 [2] 35 e8 [2] 7b e4 [2] 77 ee [2] 60 e5 [2] 7b ab [2] 46 }

  condition:
    any of them
}