rule TTP_XOR_MULT_DOSStub_468b {
  strings:
    $key_468b = { 12 e3 [2] 66 fb [2] 21 f9 [2] 66 e8 [2] 28 e4 [2] 24 ee [2] 33 e5 [2] 28 ab [2] 15 }

  condition:
    any of them
}