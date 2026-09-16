rule TTP_XOR_MULT_DOSStub_2898 {
  strings:
    $key_2898 = { 7c f0 [2] 08 e8 [2] 4f ea [2] 08 fb [2] 46 f7 [2] 4a fd [2] 5d f6 [2] 46 b8 [2] 7b }

  condition:
    any of them
}