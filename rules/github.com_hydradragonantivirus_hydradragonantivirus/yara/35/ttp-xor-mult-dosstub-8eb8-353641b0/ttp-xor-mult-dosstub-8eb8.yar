rule TTP_XOR_MULT_DOSStub_8eb8 {
  strings:
    $key_8eb8 = { da d0 [2] ae c8 [2] e9 ca [2] ae db [2] e0 d7 [2] ec dd [2] fb d6 [2] e0 98 [2] dd }

  condition:
    any of them
}