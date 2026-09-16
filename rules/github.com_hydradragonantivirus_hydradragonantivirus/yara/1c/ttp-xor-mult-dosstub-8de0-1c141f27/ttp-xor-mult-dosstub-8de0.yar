rule TTP_XOR_MULT_DOSStub_8de0 {
  strings:
    $key_8de0 = { d9 88 [2] ad 90 [2] ea 92 [2] ad 83 [2] e3 8f [2] ef 85 [2] f8 8e [2] e3 c0 [2] de }

  condition:
    any of them
}