rule TTP_XOR_MULT_DOSStub_b48b {
  strings:
    $key_b48b = { e0 e3 [2] 94 fb [2] d3 f9 [2] 94 e8 [2] da e4 [2] d6 ee [2] c1 e5 [2] da ab [2] e7 }

  condition:
    any of them
}