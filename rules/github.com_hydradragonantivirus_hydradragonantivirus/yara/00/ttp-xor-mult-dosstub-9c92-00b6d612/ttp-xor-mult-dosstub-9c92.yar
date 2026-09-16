rule TTP_XOR_MULT_DOSStub_9c92 {
  strings:
    $key_9c92 = { c8 fa [2] bc e2 [2] fb e0 [2] bc f1 [2] f2 fd [2] fe f7 [2] e9 fc [2] f2 b2 [2] cf }

  condition:
    any of them
}