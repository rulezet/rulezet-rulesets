rule TTP_XOR_MULT_DOSStub_358b {
  strings:
    $key_358b = { 61 e3 [2] 15 fb [2] 52 f9 [2] 15 e8 [2] 5b e4 [2] 57 ee [2] 40 e5 [2] 5b ab [2] 66 }

  condition:
    any of them
}