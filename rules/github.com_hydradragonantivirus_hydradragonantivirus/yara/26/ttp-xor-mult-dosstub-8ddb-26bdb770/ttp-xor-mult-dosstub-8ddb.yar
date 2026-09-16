rule TTP_XOR_MULT_DOSStub_8ddb {
  strings:
    $key_8ddb = { d9 b3 [2] ad ab [2] ea a9 [2] ad b8 [2] e3 b4 [2] ef be [2] f8 b5 [2] e3 fb [2] de }

  condition:
    any of them
}