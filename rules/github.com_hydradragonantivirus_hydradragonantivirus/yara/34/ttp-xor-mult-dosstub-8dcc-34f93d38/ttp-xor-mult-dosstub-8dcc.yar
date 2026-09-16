rule TTP_XOR_MULT_DOSStub_8dcc {
  strings:
    $key_8dcc = { d9 a4 [2] ad bc [2] ea be [2] ad af [2] e3 a3 [2] ef a9 [2] f8 a2 [2] e3 ec [2] de }

  condition:
    any of them
}