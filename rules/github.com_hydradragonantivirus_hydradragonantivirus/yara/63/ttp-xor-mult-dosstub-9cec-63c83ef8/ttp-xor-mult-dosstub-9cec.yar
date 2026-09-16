rule TTP_XOR_MULT_DOSStub_9cec {
  strings:
    $key_9cec = { c8 84 [2] bc 9c [2] fb 9e [2] bc 8f [2] f2 83 [2] fe 89 [2] e9 82 [2] f2 cc [2] cf }

  condition:
    any of them
}