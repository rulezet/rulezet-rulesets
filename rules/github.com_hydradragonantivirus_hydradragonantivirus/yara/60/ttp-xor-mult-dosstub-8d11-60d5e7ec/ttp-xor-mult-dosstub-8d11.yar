rule TTP_XOR_MULT_DOSStub_8d11 {
  strings:
    $key_8d11 = { d9 79 [2] ad 61 [2] ea 63 [2] ad 72 [2] e3 7e [2] ef 74 [2] f8 7f [2] e3 31 [2] de }

  condition:
    any of them
}