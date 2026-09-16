rule TTP_XOR_MULT_DOSStub_8d88 {
  strings:
    $key_8d88 = { d9 e0 [2] ad f8 [2] ea fa [2] ad eb [2] e3 e7 [2] ef ed [2] f8 e6 [2] e3 a8 [2] de }

  condition:
    any of them
}