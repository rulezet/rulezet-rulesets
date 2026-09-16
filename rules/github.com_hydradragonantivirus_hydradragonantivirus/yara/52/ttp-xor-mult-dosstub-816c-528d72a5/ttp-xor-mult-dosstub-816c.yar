rule TTP_XOR_MULT_DOSStub_816c {
  strings:
    $key_816c = { d5 04 [2] a1 1c [2] e6 1e [2] a1 0f [2] ef 03 [2] e3 09 [2] f4 02 [2] ef 4c [2] d2 }

  condition:
    any of them
}