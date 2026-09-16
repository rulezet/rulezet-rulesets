rule TTP_XOR_MULT_DOSStub_8d83 {
  strings:
    $key_8d83 = { d9 eb [2] ad f3 [2] ea f1 [2] ad e0 [2] e3 ec [2] ef e6 [2] f8 ed [2] e3 a3 [2] de }

  condition:
    any of them
}