rule TTP_XOR_MULT_DOSStub_81ea {
  strings:
    $key_81ea = { d5 82 [2] a1 9a [2] e6 98 [2] a1 89 [2] ef 85 [2] e3 8f [2] f4 84 [2] ef ca [2] d2 }

  condition:
    any of them
}