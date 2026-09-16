rule TTP_XOR_MULT_DOSStub_8d3c {
  strings:
    $key_8d3c = { d9 54 [2] ad 4c [2] ea 4e [2] ad 5f [2] e3 53 [2] ef 59 [2] f8 52 [2] e3 1c [2] de }

  condition:
    any of them
}