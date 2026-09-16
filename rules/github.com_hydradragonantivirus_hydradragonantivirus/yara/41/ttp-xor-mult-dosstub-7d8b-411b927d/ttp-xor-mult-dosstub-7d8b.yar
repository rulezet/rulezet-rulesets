rule TTP_XOR_MULT_DOSStub_7d8b {
  strings:
    $key_7d8b = { 29 e3 [2] 5d fb [2] 1a f9 [2] 5d e8 [2] 13 e4 [2] 1f ee [2] 08 e5 [2] 13 ab [2] 2e }

  condition:
    any of them
}