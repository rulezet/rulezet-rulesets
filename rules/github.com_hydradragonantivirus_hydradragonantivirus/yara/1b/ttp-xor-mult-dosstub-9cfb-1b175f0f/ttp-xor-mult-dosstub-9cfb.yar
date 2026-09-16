rule TTP_XOR_MULT_DOSStub_9cfb {
  strings:
    $key_9cfb = { c8 93 [2] bc 8b [2] fb 89 [2] bc 98 [2] f2 94 [2] fe 9e [2] e9 95 [2] f2 db [2] cf }

  condition:
    any of them
}