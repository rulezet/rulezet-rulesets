rule TTP_XOR_MULT_DOSStub_8ea6 {
  strings:
    $key_8ea6 = { da ce [2] ae d6 [2] e9 d4 [2] ae c5 [2] e0 c9 [2] ec c3 [2] fb c8 [2] e0 86 [2] dd }

  condition:
    any of them
}