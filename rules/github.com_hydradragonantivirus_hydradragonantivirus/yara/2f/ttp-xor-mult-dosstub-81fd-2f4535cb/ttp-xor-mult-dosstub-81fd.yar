rule TTP_XOR_MULT_DOSStub_81fd {
  strings:
    $key_81fd = { d5 95 [2] a1 8d [2] e6 8f [2] a1 9e [2] ef 92 [2] e3 98 [2] f4 93 [2] ef dd [2] d2 }

  condition:
    any of them
}