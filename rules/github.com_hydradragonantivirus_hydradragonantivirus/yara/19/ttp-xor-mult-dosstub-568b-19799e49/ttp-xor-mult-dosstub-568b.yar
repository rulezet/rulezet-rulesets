rule TTP_XOR_MULT_DOSStub_568b {
  strings:
    $key_568b = { 02 e3 [2] 76 fb [2] 31 f9 [2] 76 e8 [2] 38 e4 [2] 34 ee [2] 23 e5 [2] 38 ab [2] 05 }

  condition:
    any of them
}