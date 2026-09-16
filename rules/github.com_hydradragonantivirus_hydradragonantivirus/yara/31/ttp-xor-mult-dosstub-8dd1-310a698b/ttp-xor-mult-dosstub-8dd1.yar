rule TTP_XOR_MULT_DOSStub_8dd1 {
  strings:
    $key_8dd1 = { d9 b9 [2] ad a1 [2] ea a3 [2] ad b2 [2] e3 be [2] ef b4 [2] f8 bf [2] e3 f1 [2] de }

  condition:
    any of them
}