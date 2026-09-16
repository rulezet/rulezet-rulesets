rule TTP_XOR_MULT_DOSStub_8d69 {
  strings:
    $key_8d69 = { d9 01 [2] ad 19 [2] ea 1b [2] ad 0a [2] e3 06 [2] ef 0c [2] f8 07 [2] e3 49 [2] de }

  condition:
    any of them
}