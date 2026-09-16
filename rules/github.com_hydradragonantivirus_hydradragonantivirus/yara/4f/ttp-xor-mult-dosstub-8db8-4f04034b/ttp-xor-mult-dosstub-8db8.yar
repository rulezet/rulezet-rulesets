rule TTP_XOR_MULT_DOSStub_8db8 {
  strings:
    $key_8db8 = { d9 d0 [2] ad c8 [2] ea ca [2] ad db [2] e3 d7 [2] ef dd [2] f8 d6 [2] e3 98 [2] de }

  condition:
    any of them
}