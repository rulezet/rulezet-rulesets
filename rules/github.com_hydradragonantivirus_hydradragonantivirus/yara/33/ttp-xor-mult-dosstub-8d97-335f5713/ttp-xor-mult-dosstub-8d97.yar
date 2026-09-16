rule TTP_XOR_MULT_DOSStub_8d97 {
  strings:
    $key_8d97 = { d9 ff [2] ad e7 [2] ea e5 [2] ad f4 [2] e3 f8 [2] ef f2 [2] f8 f9 [2] e3 b7 [2] de }

  condition:
    any of them
}