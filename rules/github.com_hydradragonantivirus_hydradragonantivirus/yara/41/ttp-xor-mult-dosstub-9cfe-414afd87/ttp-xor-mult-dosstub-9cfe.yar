rule TTP_XOR_MULT_DOSStub_9cfe {
  strings:
    $key_9cfe = { c8 96 [2] bc 8e [2] fb 8c [2] bc 9d [2] f2 91 [2] fe 9b [2] e9 90 [2] f2 de [2] cf }

  condition:
    any of them
}