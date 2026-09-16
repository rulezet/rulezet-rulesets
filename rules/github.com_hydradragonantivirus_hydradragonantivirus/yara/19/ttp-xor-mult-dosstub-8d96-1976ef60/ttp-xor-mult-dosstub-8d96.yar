rule TTP_XOR_MULT_DOSStub_8d96 {
  strings:
    $key_8d96 = { d9 fe [2] ad e6 [2] ea e4 [2] ad f5 [2] e3 f9 [2] ef f3 [2] f8 f8 [2] e3 b6 [2] de }

  condition:
    any of them
}