rule TTP_XOR_MULT_DOSStub_8d82 {
  strings:
    $key_8d82 = { d9 ea [2] ad f2 [2] ea f0 [2] ad e1 [2] e3 ed [2] ef e7 [2] f8 ec [2] e3 a2 [2] de }

  condition:
    any of them
}