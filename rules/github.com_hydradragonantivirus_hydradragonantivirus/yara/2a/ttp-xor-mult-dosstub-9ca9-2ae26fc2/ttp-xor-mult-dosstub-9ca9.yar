rule TTP_XOR_MULT_DOSStub_9ca9 {
  strings:
    $key_9ca9 = { c8 c1 [2] bc d9 [2] fb db [2] bc ca [2] f2 c6 [2] fe cc [2] e9 c7 [2] f2 89 [2] cf }

  condition:
    any of them
}