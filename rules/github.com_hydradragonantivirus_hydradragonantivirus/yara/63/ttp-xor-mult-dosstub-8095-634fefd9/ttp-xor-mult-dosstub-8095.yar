rule TTP_XOR_MULT_DOSStub_8095 {
  strings:
    $key_8095 = { d4 fd [2] a0 e5 [2] e7 e7 [2] a0 f6 [2] ee fa [2] e2 f0 [2] f5 fb [2] ee b5 [2] d3 }

  condition:
    any of them
}