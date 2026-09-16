rule TTP_XOR_MULT_DOSStub_8137 {
  strings:
    $key_8137 = { d5 5f [2] a1 47 [2] e6 45 [2] a1 54 [2] ef 58 [2] e3 52 [2] f4 59 [2] ef 17 [2] d2 }

  condition:
    any of them
}