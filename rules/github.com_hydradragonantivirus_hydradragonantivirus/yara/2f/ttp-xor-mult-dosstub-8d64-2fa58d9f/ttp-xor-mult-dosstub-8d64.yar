rule TTP_XOR_MULT_DOSStub_8d64 {
  strings:
    $key_8d64 = { d9 0c [2] ad 14 [2] ea 16 [2] ad 07 [2] e3 0b [2] ef 01 [2] f8 0a [2] e3 44 [2] de }

  condition:
    any of them
}