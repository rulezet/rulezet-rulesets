rule TTP_XOR_MULT_DOSStub_558b {
  strings:
    $key_558b = { 01 e3 [2] 75 fb [2] 32 f9 [2] 75 e8 [2] 3b e4 [2] 37 ee [2] 20 e5 [2] 3b ab [2] 06 }

  condition:
    any of them
}