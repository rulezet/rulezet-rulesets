rule TTP_XOR_MULT_DOSStub_8eba {
  strings:
    $key_8eba = { da d2 [2] ae ca [2] e9 c8 [2] ae d9 [2] e0 d5 [2] ec df [2] fb d4 [2] e0 9a [2] dd }

  condition:
    any of them
}