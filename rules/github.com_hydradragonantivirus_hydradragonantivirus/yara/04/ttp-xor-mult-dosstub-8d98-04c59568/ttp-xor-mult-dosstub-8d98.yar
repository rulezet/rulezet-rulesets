rule TTP_XOR_MULT_DOSStub_8d98 {
  strings:
    $key_8d98 = { d9 f0 [2] ad e8 [2] ea ea [2] ad fb [2] e3 f7 [2] ef fd [2] f8 f6 [2] e3 b8 [2] de }

  condition:
    any of them
}