rule TTP_XOR_MULT_DOSStub_3898 {
  strings:
    $key_3898 = { 6c f0 [2] 18 e8 [2] 5f ea [2] 18 fb [2] 56 f7 [2] 5a fd [2] 4d f6 [2] 56 b8 [2] 6b }

  condition:
    any of them
}