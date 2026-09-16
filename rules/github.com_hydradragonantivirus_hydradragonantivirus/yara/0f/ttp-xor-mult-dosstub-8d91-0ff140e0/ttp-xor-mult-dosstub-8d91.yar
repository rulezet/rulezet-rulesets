rule TTP_XOR_MULT_DOSStub_8d91 {
  strings:
    $key_8d91 = { d9 f9 [2] ad e1 [2] ea e3 [2] ad f2 [2] e3 fe [2] ef f4 [2] f8 ff [2] e3 b1 [2] de }

  condition:
    any of them
}