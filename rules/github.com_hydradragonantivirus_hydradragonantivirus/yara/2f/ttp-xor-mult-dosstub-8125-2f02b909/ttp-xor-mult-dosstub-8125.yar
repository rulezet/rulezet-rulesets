rule TTP_XOR_MULT_DOSStub_8125 {
  strings:
    $key_8125 = { d5 4d [2] a1 55 [2] e6 57 [2] a1 46 [2] ef 4a [2] e3 40 [2] f4 4b [2] ef 05 [2] d2 }

  condition:
    any of them
}