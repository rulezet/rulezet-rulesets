rule TTP_XOR_MULT_DOSStub_83c8 {
  strings:
    $key_83c8 = { d7 a0 [2] a3 b8 [2] e4 ba [2] a3 ab [2] ed a7 [2] e1 ad [2] f6 a6 [2] ed e8 [2] d0 }

  condition:
    any of them
}