rule TTP_XOR_MULT_DOSStub_368b {
  strings:
    $key_368b = { 62 e3 [2] 16 fb [2] 51 f9 [2] 16 e8 [2] 58 e4 [2] 54 ee [2] 43 e5 [2] 58 ab [2] 65 }

  condition:
    any of them
}