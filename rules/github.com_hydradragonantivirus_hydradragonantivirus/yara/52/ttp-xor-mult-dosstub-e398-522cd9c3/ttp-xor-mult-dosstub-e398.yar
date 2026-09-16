rule TTP_XOR_MULT_DOSStub_e398 {
  strings:
    $key_e398 = { b7 f0 [2] c3 e8 [2] 84 ea [2] c3 fb [2] 8d f7 [2] 81 fd [2] 96 f6 [2] 8d b8 [2] b0 }

  condition:
    any of them
}