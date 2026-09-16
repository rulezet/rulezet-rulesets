rule TTP_XOR_MULT_DOSStub_a698 {
  strings:
    $key_a698 = { f2 f0 [2] 86 e8 [2] c1 ea [2] 86 fb [2] c8 f7 [2] c4 fd [2] d3 f6 [2] c8 b8 [2] f5 }

  condition:
    any of them
}