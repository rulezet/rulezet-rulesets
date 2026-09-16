rule TTP_XOR_MULT_DOSStub_9c87 {
  strings:
    $key_9c87 = { c8 ef [2] bc f7 [2] fb f5 [2] bc e4 [2] f2 e8 [2] fe e2 [2] e9 e9 [2] f2 a7 [2] cf }

  condition:
    any of them
}