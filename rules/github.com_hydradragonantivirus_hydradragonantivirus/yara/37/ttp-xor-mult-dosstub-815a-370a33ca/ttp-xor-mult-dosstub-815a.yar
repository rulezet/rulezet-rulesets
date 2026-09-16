rule TTP_XOR_MULT_DOSStub_815a {
  strings:
    $key_815a = { d5 32 [2] a1 2a [2] e6 28 [2] a1 39 [2] ef 35 [2] e3 3f [2] f4 34 [2] ef 7a [2] d2 }

  condition:
    any of them
}