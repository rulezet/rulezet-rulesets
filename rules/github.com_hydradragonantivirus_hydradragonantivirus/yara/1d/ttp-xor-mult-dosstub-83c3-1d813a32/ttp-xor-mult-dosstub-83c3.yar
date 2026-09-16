rule TTP_XOR_MULT_DOSStub_83c3 {
  strings:
    $key_83c3 = { d7 ab [2] a3 b3 [2] e4 b1 [2] a3 a0 [2] ed ac [2] e1 a6 [2] f6 ad [2] ed e3 [2] d0 }

  condition:
    any of them
}