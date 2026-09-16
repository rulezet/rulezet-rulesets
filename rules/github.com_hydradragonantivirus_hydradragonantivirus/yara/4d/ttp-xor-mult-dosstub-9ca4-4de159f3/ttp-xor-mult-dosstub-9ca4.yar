rule TTP_XOR_MULT_DOSStub_9ca4 {
  strings:
    $key_9ca4 = { c8 cc [2] bc d4 [2] fb d6 [2] bc c7 [2] f2 cb [2] fe c1 [2] e9 ca [2] f2 84 [2] cf }

  condition:
    any of them
}