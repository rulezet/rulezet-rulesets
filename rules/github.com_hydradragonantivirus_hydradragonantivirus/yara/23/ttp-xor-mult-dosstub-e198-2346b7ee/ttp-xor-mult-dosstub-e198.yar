rule TTP_XOR_MULT_DOSStub_e198 {
  strings:
    $key_e198 = { b5 f0 [2] c1 e8 [2] 86 ea [2] c1 fb [2] 8f f7 [2] 83 fd [2] 94 f6 [2] 8f b8 [2] b2 }

  condition:
    any of them
}