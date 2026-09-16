rule TTP_XOR_MULT_DOSStub_8d85 {
  strings:
    $key_8d85 = { d9 ed [2] ad f5 [2] ea f7 [2] ad e6 [2] e3 ea [2] ef e0 [2] f8 eb [2] e3 a5 [2] de }

  condition:
    any of them
}