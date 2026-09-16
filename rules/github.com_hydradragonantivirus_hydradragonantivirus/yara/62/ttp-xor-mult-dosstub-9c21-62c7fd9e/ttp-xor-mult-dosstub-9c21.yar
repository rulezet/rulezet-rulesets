rule TTP_XOR_MULT_DOSStub_9c21 {
  strings:
    $key_9c21 = { c8 49 [2] bc 51 [2] fb 53 [2] bc 42 [2] f2 4e [2] fe 44 [2] e9 4f [2] f2 01 [2] cf }

  condition:
    any of them
}