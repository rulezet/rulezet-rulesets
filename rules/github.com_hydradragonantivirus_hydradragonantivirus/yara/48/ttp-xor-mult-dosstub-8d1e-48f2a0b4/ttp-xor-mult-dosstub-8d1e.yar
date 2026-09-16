rule TTP_XOR_MULT_DOSStub_8d1e {
  strings:
    $key_8d1e = { d9 76 [2] ad 6e [2] ea 6c [2] ad 7d [2] e3 71 [2] ef 7b [2] f8 70 [2] e3 3e [2] de }

  condition:
    any of them
}