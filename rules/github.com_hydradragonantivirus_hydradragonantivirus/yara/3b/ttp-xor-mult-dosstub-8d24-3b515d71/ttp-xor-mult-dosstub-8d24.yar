rule TTP_XOR_MULT_DOSStub_8d24 {
  strings:
    $key_8d24 = { d9 4c [2] ad 54 [2] ea 56 [2] ad 47 [2] e3 4b [2] ef 41 [2] f8 4a [2] e3 04 [2] de }

  condition:
    any of them
}