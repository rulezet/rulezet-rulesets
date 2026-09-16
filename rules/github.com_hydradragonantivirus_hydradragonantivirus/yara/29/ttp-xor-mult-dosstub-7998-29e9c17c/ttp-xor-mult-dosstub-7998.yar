rule TTP_XOR_MULT_DOSStub_7998 {
  strings:
    $key_7998 = { 2d f0 [2] 59 e8 [2] 1e ea [2] 59 fb [2] 17 f7 [2] 1b fd [2] 0c f6 [2] 17 b8 [2] 2a }

  condition:
    any of them
}