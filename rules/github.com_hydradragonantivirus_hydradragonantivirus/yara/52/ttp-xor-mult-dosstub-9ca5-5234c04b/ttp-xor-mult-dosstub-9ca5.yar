rule TTP_XOR_MULT_DOSStub_9ca5 {
  strings:
    $key_9ca5 = { c8 cd [2] bc d5 [2] fb d7 [2] bc c6 [2] f2 ca [2] fe c0 [2] e9 cb [2] f2 85 [2] cf }

  condition:
    any of them
}