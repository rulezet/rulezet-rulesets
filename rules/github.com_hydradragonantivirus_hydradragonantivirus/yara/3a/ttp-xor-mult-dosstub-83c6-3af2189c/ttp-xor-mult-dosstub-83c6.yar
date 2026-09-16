rule TTP_XOR_MULT_DOSStub_83c6 {
  strings:
    $key_83c6 = { d7 ae [2] a3 b6 [2] e4 b4 [2] a3 a5 [2] ed a9 [2] e1 a3 [2] f6 a8 [2] ed e6 [2] d0 }

  condition:
    any of them
}