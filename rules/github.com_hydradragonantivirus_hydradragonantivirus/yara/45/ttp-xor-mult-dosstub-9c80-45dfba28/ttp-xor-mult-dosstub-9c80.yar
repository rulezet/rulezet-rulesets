rule TTP_XOR_MULT_DOSStub_9c80 {
  strings:
    $key_9c80 = { c8 e8 [2] bc f0 [2] fb f2 [2] bc e3 [2] f2 ef [2] fe e5 [2] e9 ee [2] f2 a0 [2] cf }

  condition:
    any of them
}