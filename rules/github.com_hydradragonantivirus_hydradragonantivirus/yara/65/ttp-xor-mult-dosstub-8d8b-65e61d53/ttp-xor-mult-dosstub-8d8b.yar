rule TTP_XOR_MULT_DOSStub_8d8b {
  strings:
    $key_8d8b = { d9 e3 [2] ad fb [2] ea f9 [2] ad e8 [2] e3 e4 [2] ef ee [2] f8 e5 [2] e3 ab [2] de }

  condition:
    any of them
}