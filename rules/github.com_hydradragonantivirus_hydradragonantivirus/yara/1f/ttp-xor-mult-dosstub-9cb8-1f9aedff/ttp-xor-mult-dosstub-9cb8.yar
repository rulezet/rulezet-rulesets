rule TTP_XOR_MULT_DOSStub_9cb8 {
  strings:
    $key_9cb8 = { c8 d0 [2] bc c8 [2] fb ca [2] bc db [2] f2 d7 [2] fe dd [2] e9 d6 [2] f2 98 [2] cf }

  condition:
    any of them
}