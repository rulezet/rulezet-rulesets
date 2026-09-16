rule TTP_XOR_MULT_DOSStub_879e {
  strings:
    $key_879e = { d3 f6 [2] a7 ee [2] e0 ec [2] a7 fd [2] e9 f1 [2] e5 fb [2] f2 f0 [2] e9 be [2] d4 }

  condition:
    any of them
}