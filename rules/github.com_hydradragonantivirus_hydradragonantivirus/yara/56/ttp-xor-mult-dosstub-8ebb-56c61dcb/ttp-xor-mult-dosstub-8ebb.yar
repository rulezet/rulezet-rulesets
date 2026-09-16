rule TTP_XOR_MULT_DOSStub_8ebb {
  strings:
    $key_8ebb = { da d3 [2] ae cb [2] e9 c9 [2] ae d8 [2] e0 d4 [2] ec de [2] fb d5 [2] e0 9b [2] dd }

  condition:
    any of them
}