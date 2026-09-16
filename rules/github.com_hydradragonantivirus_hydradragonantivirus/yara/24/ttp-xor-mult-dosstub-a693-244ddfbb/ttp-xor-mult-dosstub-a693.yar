rule TTP_XOR_MULT_DOSStub_a693 {
  strings:
    $key_a693 = { f2 fb [2] 86 e3 [2] c1 e1 [2] 86 f0 [2] c8 fc [2] c4 f6 [2] d3 fd [2] c8 b3 [2] f5 }

  condition:
    any of them
}