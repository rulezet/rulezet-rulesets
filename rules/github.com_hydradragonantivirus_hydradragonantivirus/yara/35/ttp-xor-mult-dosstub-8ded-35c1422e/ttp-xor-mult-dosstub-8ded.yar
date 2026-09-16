rule TTP_XOR_MULT_DOSStub_8ded {
  strings:
    $key_8ded = { d9 85 [2] ad 9d [2] ea 9f [2] ad 8e [2] e3 82 [2] ef 88 [2] f8 83 [2] e3 cd [2] de }

  condition:
    any of them
}