rule TTP_XOR_MULT_DOSStub_8ebc {
  strings:
    $key_8ebc = { da d4 [2] ae cc [2] e9 ce [2] ae df [2] e0 d3 [2] ec d9 [2] fb d2 [2] e0 9c [2] dd }

  condition:
    any of them
}