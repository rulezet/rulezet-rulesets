rule TTP_XOR_MULT_DOSStub_9cad {
  strings:
    $key_9cad = { c8 c5 [2] bc dd [2] fb df [2] bc ce [2] f2 c2 [2] fe c8 [2] e9 c3 [2] f2 8d [2] cf }

  condition:
    any of them
}