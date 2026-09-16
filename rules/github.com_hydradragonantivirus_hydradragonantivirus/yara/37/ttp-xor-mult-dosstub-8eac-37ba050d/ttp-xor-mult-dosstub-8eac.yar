rule TTP_XOR_MULT_DOSStub_8eac {
  strings:
    $key_8eac = { da c4 [2] ae dc [2] e9 de [2] ae cf [2] e0 c3 [2] ec c9 [2] fb c2 [2] e0 8c [2] dd }

  condition:
    any of them
}