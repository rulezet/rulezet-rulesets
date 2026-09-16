rule TTP_XOR_MULT_DOSStub_408b {
  strings:
    $key_408b = { 14 e3 [2] 60 fb [2] 27 f9 [2] 60 e8 [2] 2e e4 [2] 22 ee [2] 35 e5 [2] 2e ab [2] 13 }

  condition:
    any of them
}