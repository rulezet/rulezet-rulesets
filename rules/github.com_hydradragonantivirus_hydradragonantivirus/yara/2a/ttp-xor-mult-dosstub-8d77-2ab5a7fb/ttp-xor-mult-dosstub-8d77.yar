rule TTP_XOR_MULT_DOSStub_8d77 {
  strings:
    $key_8d77 = { d9 1f [2] ad 07 [2] ea 05 [2] ad 14 [2] e3 18 [2] ef 12 [2] f8 19 [2] e3 57 [2] de }

  condition:
    any of them
}