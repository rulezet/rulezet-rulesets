rule TTP_XOR_MULT_DOSStub_268b {
  strings:
    $key_268b = { 72 e3 [2] 06 fb [2] 41 f9 [2] 06 e8 [2] 48 e4 [2] 44 ee [2] 53 e5 [2] 48 ab [2] 75 }

  condition:
    any of them
}