rule TTP_XOR_MULT_DOSStub_8dec {
  strings:
    $key_8dec = { d9 84 [2] ad 9c [2] ea 9e [2] ad 8f [2] e3 83 [2] ef 89 [2] f8 82 [2] e3 cc [2] de }

  condition:
    any of them
}