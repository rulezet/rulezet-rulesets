rule TTP_XOR_MULT_DOSStub_8798 {
  strings:
    $key_8798 = { d3 f0 [2] a7 e8 [2] e0 ea [2] a7 fb [2] e9 f7 [2] e5 fd [2] f2 f6 [2] e9 b8 [2] d4 }

  condition:
    any of them
}