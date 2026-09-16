rule TTP_XOR_MULT_DOSStub_8dd7 {
  strings:
    $key_8dd7 = { d9 bf [2] ad a7 [2] ea a5 [2] ad b4 [2] e3 b8 [2] ef b2 [2] f8 b9 [2] e3 f7 [2] de }

  condition:
    any of them
}