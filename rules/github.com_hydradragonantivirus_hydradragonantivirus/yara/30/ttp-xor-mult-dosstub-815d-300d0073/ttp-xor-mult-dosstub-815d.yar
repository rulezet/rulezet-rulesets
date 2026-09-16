rule TTP_XOR_MULT_DOSStub_815d {
  strings:
    $key_815d = { d5 35 [2] a1 2d [2] e6 2f [2] a1 3e [2] ef 32 [2] e3 38 [2] f4 33 [2] ef 7d [2] d2 }

  condition:
    any of them
}