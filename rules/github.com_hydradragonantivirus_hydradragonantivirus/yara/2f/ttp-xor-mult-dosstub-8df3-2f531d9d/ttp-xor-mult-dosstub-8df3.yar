rule TTP_XOR_MULT_DOSStub_8df3 {
  strings:
    $key_8df3 = { d9 9b [2] ad 83 [2] ea 81 [2] ad 90 [2] e3 9c [2] ef 96 [2] f8 9d [2] e3 d3 [2] de }

  condition:
    any of them
}