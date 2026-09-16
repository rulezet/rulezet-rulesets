rule TTP_XOR_MULT_DOSStub_b298 {
  strings:
    $key_b298 = { e6 f0 [2] 92 e8 [2] d5 ea [2] 92 fb [2] dc f7 [2] d0 fd [2] c7 f6 [2] dc b8 [2] e1 }

  condition:
    any of them
}