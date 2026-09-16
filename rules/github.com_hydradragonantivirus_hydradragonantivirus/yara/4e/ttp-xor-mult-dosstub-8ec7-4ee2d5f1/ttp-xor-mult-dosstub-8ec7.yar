rule TTP_XOR_MULT_DOSStub_8ec7 {
  strings:
    $key_8ec7 = { da af [2] ae b7 [2] e9 b5 [2] ae a4 [2] e0 a8 [2] ec a2 [2] fb a9 [2] e0 e7 [2] dd }

  condition:
    any of them
}