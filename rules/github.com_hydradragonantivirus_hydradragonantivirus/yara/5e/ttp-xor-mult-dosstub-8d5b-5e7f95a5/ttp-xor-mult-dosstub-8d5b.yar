rule TTP_XOR_MULT_DOSStub_8d5b {
  strings:
    $key_8d5b = { d9 33 [2] ad 2b [2] ea 29 [2] ad 38 [2] e3 34 [2] ef 3e [2] f8 35 [2] e3 7b [2] de }

  condition:
    any of them
}