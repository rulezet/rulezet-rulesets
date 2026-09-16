rule TTP_XOR_MULT_DOSStub_8d35 {
  strings:
    $key_8d35 = { d9 5d [2] ad 45 [2] ea 47 [2] ad 56 [2] e3 5a [2] ef 50 [2] f8 5b [2] e3 15 [2] de }

  condition:
    any of them
}