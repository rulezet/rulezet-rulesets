rule TTP_XOR_MULT_DOSStub_8d71 {
  strings:
    $key_8d71 = { d9 19 [2] ad 01 [2] ea 03 [2] ad 12 [2] e3 1e [2] ef 14 [2] f8 1f [2] e3 51 [2] de }

  condition:
    any of them
}