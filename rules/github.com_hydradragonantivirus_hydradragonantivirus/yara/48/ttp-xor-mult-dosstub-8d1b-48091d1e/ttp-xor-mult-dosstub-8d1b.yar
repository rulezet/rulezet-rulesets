rule TTP_XOR_MULT_DOSStub_8d1b {
  strings:
    $key_8d1b = { d9 73 [2] ad 6b [2] ea 69 [2] ad 78 [2] e3 74 [2] ef 7e [2] f8 75 [2] e3 3b [2] de }

  condition:
    any of them
}