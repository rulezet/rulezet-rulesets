rule TTP_XOR_MULT_DOSStub_8dce {
  strings:
    $key_8dce = { d9 a6 [2] ad be [2] ea bc [2] ad ad [2] e3 a1 [2] ef ab [2] f8 a0 [2] e3 ee [2] de }

  condition:
    any of them
}