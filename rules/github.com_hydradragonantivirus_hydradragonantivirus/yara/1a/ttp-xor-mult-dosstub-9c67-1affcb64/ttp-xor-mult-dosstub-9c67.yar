rule TTP_XOR_MULT_DOSStub_9c67 {
  strings:
    $key_9c67 = { c8 0f [2] bc 17 [2] fb 15 [2] bc 04 [2] f2 08 [2] fe 02 [2] e9 09 [2] f2 47 [2] cf }

  condition:
    any of them
}