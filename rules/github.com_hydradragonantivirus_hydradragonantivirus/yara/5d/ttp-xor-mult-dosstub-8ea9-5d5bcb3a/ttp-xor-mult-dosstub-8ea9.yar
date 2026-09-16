rule TTP_XOR_MULT_DOSStub_8ea9 {
  strings:
    $key_8ea9 = { da c1 [2] ae d9 [2] e9 db [2] ae ca [2] e0 c6 [2] ec cc [2] fb c7 [2] e0 89 [2] dd }

  condition:
    any of them
}