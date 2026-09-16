rule TTP_XOR_MULT_DOSStub_8d61 {
  strings:
    $key_8d61 = { d9 09 [2] ad 11 [2] ea 13 [2] ad 02 [2] e3 0e [2] ef 04 [2] f8 0f [2] e3 41 [2] de }

  condition:
    any of them
}