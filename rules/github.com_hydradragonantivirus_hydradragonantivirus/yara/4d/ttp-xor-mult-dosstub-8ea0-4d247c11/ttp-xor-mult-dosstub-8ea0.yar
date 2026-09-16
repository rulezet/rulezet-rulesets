rule TTP_XOR_MULT_DOSStub_8ea0 {
  strings:
    $key_8ea0 = { da c8 [2] ae d0 [2] e9 d2 [2] ae c3 [2] e0 cf [2] ec c5 [2] fb ce [2] e0 80 [2] dd }

  condition:
    any of them
}