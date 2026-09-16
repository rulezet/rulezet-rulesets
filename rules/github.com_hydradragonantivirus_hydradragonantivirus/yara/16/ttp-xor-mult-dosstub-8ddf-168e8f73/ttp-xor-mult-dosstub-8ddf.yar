rule TTP_XOR_MULT_DOSStub_8ddf {
  strings:
    $key_8ddf = { d9 b7 [2] ad af [2] ea ad [2] ad bc [2] e3 b0 [2] ef ba [2] f8 b1 [2] e3 ff [2] de }

  condition:
    any of them
}