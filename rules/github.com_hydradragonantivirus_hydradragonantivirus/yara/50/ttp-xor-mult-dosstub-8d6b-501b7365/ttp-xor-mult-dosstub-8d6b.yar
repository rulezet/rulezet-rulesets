rule TTP_XOR_MULT_DOSStub_8d6b {
  strings:
    $key_8d6b = { d9 03 [2] ad 1b [2] ea 19 [2] ad 08 [2] e3 04 [2] ef 0e [2] f8 05 [2] e3 4b [2] de }

  condition:
    any of them
}