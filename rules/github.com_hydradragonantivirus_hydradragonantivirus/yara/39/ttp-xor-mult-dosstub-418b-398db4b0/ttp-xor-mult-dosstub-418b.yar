rule TTP_XOR_MULT_DOSStub_418b {
  strings:
    $key_418b = { 15 e3 [2] 61 fb [2] 26 f9 [2] 61 e8 [2] 2f e4 [2] 23 ee [2] 34 e5 [2] 2f ab [2] 12 }

  condition:
    any of them
}