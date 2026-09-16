rule TTP_XOR_MULT_DOSStub_9c9f {
  strings:
    $key_9c9f = { c8 f7 [2] bc ef [2] fb ed [2] bc fc [2] f2 f0 [2] fe fa [2] e9 f1 [2] f2 bf [2] cf }

  condition:
    any of them
}