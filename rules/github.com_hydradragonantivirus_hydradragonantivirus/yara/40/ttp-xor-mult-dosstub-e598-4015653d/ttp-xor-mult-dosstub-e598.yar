rule TTP_XOR_MULT_DOSStub_e598 {
  strings:
    $key_e598 = { b1 f0 [2] c5 e8 [2] 82 ea [2] c5 fb [2] 8b f7 [2] 87 fd [2] 90 f6 [2] 8b b8 [2] b6 }

  condition:
    any of them
}