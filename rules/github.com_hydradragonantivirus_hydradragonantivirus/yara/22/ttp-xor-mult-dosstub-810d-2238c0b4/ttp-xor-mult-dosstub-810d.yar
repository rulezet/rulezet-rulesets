rule TTP_XOR_MULT_DOSStub_810d {
  strings:
    $key_810d = { d5 65 [2] a1 7d [2] e6 7f [2] a1 6e [2] ef 62 [2] e3 68 [2] f4 63 [2] ef 2d [2] d2 }

  condition:
    any of them
}