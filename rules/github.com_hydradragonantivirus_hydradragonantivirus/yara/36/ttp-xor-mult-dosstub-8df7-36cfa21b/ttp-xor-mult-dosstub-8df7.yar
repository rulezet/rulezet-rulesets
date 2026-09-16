rule TTP_XOR_MULT_DOSStub_8df7 {
  strings:
    $key_8df7 = { d9 9f [2] ad 87 [2] ea 85 [2] ad 94 [2] e3 98 [2] ef 92 [2] f8 99 [2] e3 d7 [2] de }

  condition:
    any of them
}