rule TTP_XOR_MULT_DOSStub_9ca2 {
  strings:
    $key_9ca2 = { c8 ca [2] bc d2 [2] fb d0 [2] bc c1 [2] f2 cd [2] fe c7 [2] e9 cc [2] f2 82 [2] cf }

  condition:
    any of them
}