rule TTP_XOR_MULT_DOSStub_8eaa {
  strings:
    $key_8eaa = { da c2 [2] ae da [2] e9 d8 [2] ae c9 [2] e0 c5 [2] ec cf [2] fb c4 [2] e0 8a [2] dd }

  condition:
    any of them
}