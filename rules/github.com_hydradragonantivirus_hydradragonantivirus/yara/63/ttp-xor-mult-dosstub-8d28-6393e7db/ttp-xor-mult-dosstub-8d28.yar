rule TTP_XOR_MULT_DOSStub_8d28 {
  strings:
    $key_8d28 = { d9 40 [2] ad 58 [2] ea 5a [2] ad 4b [2] e3 47 [2] ef 4d [2] f8 46 [2] e3 08 [2] de }

  condition:
    any of them
}