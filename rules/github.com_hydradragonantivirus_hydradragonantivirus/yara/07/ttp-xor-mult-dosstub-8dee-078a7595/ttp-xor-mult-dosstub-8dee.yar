rule TTP_XOR_MULT_DOSStub_8dee {
  strings:
    $key_8dee = { d9 86 [2] ad 9e [2] ea 9c [2] ad 8d [2] e3 81 [2] ef 8b [2] f8 80 [2] e3 ce [2] de }

  condition:
    any of them
}