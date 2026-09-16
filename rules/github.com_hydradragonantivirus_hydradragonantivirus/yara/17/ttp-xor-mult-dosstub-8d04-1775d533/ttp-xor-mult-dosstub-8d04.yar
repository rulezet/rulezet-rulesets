rule TTP_XOR_MULT_DOSStub_8d04 {
  strings:
    $key_8d04 = { d9 6c [2] ad 74 [2] ea 76 [2] ad 67 [2] e3 6b [2] ef 61 [2] f8 6a [2] e3 24 [2] de }

  condition:
    any of them
}