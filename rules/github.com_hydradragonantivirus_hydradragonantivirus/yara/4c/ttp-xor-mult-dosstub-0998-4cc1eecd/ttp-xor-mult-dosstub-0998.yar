rule TTP_XOR_MULT_DOSStub_0998 {
  strings:
    $key_0998 = { 5d f0 [2] 29 e8 [2] 6e ea [2] 29 fb [2] 67 f7 [2] 6b fd [2] 7c f6 [2] 67 b8 [2] 5a }

  condition:
    any of them
}