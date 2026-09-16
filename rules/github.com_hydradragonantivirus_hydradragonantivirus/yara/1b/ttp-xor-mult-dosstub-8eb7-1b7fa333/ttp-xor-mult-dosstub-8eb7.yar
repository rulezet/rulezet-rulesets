rule TTP_XOR_MULT_DOSStub_8eb7 {
  strings:
    $key_8eb7 = { da df [2] ae c7 [2] e9 c5 [2] ae d4 [2] e0 d8 [2] ec d2 [2] fb d9 [2] e0 97 [2] dd }

  condition:
    any of them
}