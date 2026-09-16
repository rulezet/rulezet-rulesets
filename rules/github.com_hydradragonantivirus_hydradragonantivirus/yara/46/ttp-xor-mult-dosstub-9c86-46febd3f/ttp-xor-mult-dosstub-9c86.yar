rule TTP_XOR_MULT_DOSStub_9c86 {
  strings:
    $key_9c86 = { c8 ee [2] bc f6 [2] fb f4 [2] bc e5 [2] f2 e9 [2] fe e3 [2] e9 e8 [2] f2 a6 [2] cf }

  condition:
    any of them
}