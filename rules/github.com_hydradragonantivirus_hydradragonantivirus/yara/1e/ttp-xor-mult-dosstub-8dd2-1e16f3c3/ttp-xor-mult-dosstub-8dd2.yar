rule TTP_XOR_MULT_DOSStub_8dd2 {
  strings:
    $key_8dd2 = { d9 ba [2] ad a2 [2] ea a0 [2] ad b1 [2] e3 bd [2] ef b7 [2] f8 bc [2] e3 f2 [2] de }

  condition:
    any of them
}