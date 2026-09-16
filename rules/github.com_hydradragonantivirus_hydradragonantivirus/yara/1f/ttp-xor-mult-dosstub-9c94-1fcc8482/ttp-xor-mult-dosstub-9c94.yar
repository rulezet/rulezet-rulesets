rule TTP_XOR_MULT_DOSStub_9c94 {
  strings:
    $key_9c94 = { c8 fc [2] bc e4 [2] fb e6 [2] bc f7 [2] f2 fb [2] fe f1 [2] e9 fa [2] f2 b4 [2] cf }

  condition:
    any of them
}