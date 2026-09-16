rule TTP_XOR_MULT_DOSStub_8d9f {
  strings:
    $key_8d9f = { d9 f7 [2] ad ef [2] ea ed [2] ad fc [2] e3 f0 [2] ef fa [2] f8 f1 [2] e3 bf [2] de }

  condition:
    any of them
}