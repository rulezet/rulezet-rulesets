rule TTP_XOR_MULT_DOSStub_8de9 {
  strings:
    $key_8de9 = { d9 81 [2] ad 99 [2] ea 9b [2] ad 8a [2] e3 86 [2] ef 8c [2] f8 87 [2] e3 c9 [2] de }

  condition:
    any of them
}