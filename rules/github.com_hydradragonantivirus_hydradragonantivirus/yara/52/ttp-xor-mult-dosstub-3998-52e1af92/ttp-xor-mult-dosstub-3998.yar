rule TTP_XOR_MULT_DOSStub_3998 {
  strings:
    $key_3998 = { 6d f0 [2] 19 e8 [2] 5e ea [2] 19 fb [2] 57 f7 [2] 5b fd [2] 4c f6 [2] 57 b8 [2] 6a }

  condition:
    any of them
}