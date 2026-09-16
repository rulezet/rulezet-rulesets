rule TTP_XOR_MULT_DOSStub_8d3f {
  strings:
    $key_8d3f = { d9 57 [2] ad 4f [2] ea 4d [2] ad 5c [2] e3 50 [2] ef 5a [2] f8 51 [2] e3 1f [2] de }

  condition:
    any of them
}