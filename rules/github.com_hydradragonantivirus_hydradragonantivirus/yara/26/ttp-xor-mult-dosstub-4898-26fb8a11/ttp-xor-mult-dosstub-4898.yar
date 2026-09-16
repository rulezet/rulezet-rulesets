rule TTP_XOR_MULT_DOSStub_4898 {
  strings:
    $key_4898 = { 1c f0 [2] 68 e8 [2] 2f ea [2] 68 fb [2] 26 f7 [2] 2a fd [2] 3d f6 [2] 26 b8 [2] 1b }

  condition:
    any of them
}