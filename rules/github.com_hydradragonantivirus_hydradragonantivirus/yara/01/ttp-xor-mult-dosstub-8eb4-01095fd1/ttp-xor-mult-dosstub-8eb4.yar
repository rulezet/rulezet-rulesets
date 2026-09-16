rule TTP_XOR_MULT_DOSStub_8eb4 {
  strings:
    $key_8eb4 = { da dc [2] ae c4 [2] e9 c6 [2] ae d7 [2] e0 db [2] ec d1 [2] fb da [2] e0 94 [2] dd }

  condition:
    any of them
}