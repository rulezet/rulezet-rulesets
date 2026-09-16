rule TTP_XOR_MULT_DOSStub_e195 {
  strings:
    $key_e195 = { b5 fd [2] c1 e5 [2] 86 e7 [2] c1 f6 [2] 8f fa [2] 83 f0 [2] 94 fb [2] 8f b5 [2] b2 }

  condition:
    any of them
}