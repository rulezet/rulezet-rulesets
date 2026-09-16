rule TTP_XOR_MULT_DOSStub_8d94 {
  strings:
    $key_8d94 = { d9 fc [2] ad e4 [2] ea e6 [2] ad f7 [2] e3 fb [2] ef f1 [2] f8 fa [2] e3 b4 [2] de }

  condition:
    any of them
}