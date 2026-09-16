rule TTP_XOR_MULT_DOSStub_8de1 {
  strings:
    $key_8de1 = { d9 89 [2] ad 91 [2] ea 93 [2] ad 82 [2] e3 8e [2] ef 84 [2] f8 8f [2] e3 c1 [2] de }

  condition:
    any of them
}