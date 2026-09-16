rule TTP_XOR_MULT_DOSStub_9ccb {
  strings:
    $key_9ccb = { c8 a3 [2] bc bb [2] fb b9 [2] bc a8 [2] f2 a4 [2] fe ae [2] e9 a5 [2] f2 eb [2] cf }

  condition:
    any of them
}