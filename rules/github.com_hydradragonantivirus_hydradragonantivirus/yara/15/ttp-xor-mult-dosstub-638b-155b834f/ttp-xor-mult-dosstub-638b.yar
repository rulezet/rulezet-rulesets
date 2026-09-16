rule TTP_XOR_MULT_DOSStub_638b {
  strings:
    $key_638b = { 37 e3 [2] 43 fb [2] 04 f9 [2] 43 e8 [2] 0d e4 [2] 01 ee [2] 16 e5 [2] 0d ab [2] 30 }

  condition:
    any of them
}