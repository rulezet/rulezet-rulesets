rule TTP_XOR_MULT_DOSStub_8151 {
  strings:
    $key_8151 = { d5 39 [2] a1 21 [2] e6 23 [2] a1 32 [2] ef 3e [2] e3 34 [2] f4 3f [2] ef 71 [2] d2 }

  condition:
    any of them
}