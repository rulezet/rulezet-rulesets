rule TTP_XOR_MULT_DOSStub_816d {
  strings:
    $key_816d = { d5 05 [2] a1 1d [2] e6 1f [2] a1 0e [2] ef 02 [2] e3 08 [2] f4 03 [2] ef 4d [2] d2 }

  condition:
    any of them
}