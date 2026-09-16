rule TTP_XOR_MULT_DOSStub_81ee {
  strings:
    $key_81ee = { d5 86 [2] a1 9e [2] e6 9c [2] a1 8d [2] ef 81 [2] e3 8b [2] f4 80 [2] ef ce [2] d2 }

  condition:
    any of them
}