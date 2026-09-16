rule TTP_XOR_MULT_DOSStub_9cbb {
  strings:
    $key_9cbb = { c8 d3 [2] bc cb [2] fb c9 [2] bc d8 [2] f2 d4 [2] fe de [2] e9 d5 [2] f2 9b [2] cf }

  condition:
    any of them
}