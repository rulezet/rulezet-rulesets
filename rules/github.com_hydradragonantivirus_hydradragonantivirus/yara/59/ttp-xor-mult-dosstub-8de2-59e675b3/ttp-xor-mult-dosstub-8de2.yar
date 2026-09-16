rule TTP_XOR_MULT_DOSStub_8de2 {
  strings:
    $key_8de2 = { d9 8a [2] ad 92 [2] ea 90 [2] ad 81 [2] e3 8d [2] ef 87 [2] f8 8c [2] e3 c2 [2] de }

  condition:
    any of them
}