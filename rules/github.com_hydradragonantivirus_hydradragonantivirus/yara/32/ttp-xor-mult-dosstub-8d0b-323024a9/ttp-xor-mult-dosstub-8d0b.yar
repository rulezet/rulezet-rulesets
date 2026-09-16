rule TTP_XOR_MULT_DOSStub_8d0b {
  strings:
    $key_8d0b = { d9 63 [2] ad 7b [2] ea 79 [2] ad 68 [2] e3 64 [2] ef 6e [2] f8 65 [2] e3 2b [2] de }

  condition:
    any of them
}