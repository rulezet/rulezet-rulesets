rule TTP_XOR_MULT_DOSStub_9c53 {
  strings:
    $key_9c53 = { c8 3b [2] bc 23 [2] fb 21 [2] bc 30 [2] f2 3c [2] fe 36 [2] e9 3d [2] f2 73 [2] cf }

  condition:
    any of them
}