rule TTP_XOR_MULT_DOSStub_8ea7 {
  strings:
    $key_8ea7 = { da cf [2] ae d7 [2] e9 d5 [2] ae c4 [2] e0 c8 [2] ec c2 [2] fb c9 [2] e0 87 [2] dd }

  condition:
    any of them
}