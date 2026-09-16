rule TTP_XOR_MULT_DOSStub_8eb9 {
  strings:
    $key_8eb9 = { da d1 [2] ae c9 [2] e9 cb [2] ae da [2] e0 d6 [2] ec dc [2] fb d7 [2] e0 99 [2] dd }

  condition:
    any of them
}