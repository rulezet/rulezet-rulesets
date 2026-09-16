rule TTP_XOR_MULT_DOSStub_ab8b {
  strings:
    $key_ab8b = { ff e3 [2] 8b fb [2] cc f9 [2] 8b e8 [2] c5 e4 [2] c9 ee [2] de e5 [2] c5 ab [2] f8 }

  condition:
    any of them
}