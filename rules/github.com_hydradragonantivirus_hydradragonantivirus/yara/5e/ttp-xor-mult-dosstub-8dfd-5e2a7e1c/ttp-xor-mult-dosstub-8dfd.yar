rule TTP_XOR_MULT_DOSStub_8dfd {
  strings:
    $key_8dfd = { d9 95 [2] ad 8d [2] ea 8f [2] ad 9e [2] e3 92 [2] ef 98 [2] f8 93 [2] e3 dd [2] de }

  condition:
    any of them
}