rule TTP_XOR_MULT_DOSStub_0898 {
  strings:
    $key_0898 = { 5c f0 [2] 28 e8 [2] 6f ea [2] 28 fb [2] 66 f7 [2] 6a fd [2] 7d f6 [2] 66 b8 [2] 5b }

  condition:
    any of them
}