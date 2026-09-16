rule TTP_XOR_MULT_DOSStub_8ea5 {
  strings:
    $key_8ea5 = { da cd [2] ae d5 [2] e9 d7 [2] ae c6 [2] e0 ca [2] ec c0 [2] fb cb [2] e0 85 [2] dd }

  condition:
    any of them
}