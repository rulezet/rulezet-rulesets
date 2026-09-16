rule TTP_XOR_MULT_DOSStub_88b1 {
  strings:
    $key_88b1 = { dc d9 [2] a8 c1 [2] ef c3 [2] a8 d2 [2] e6 de [2] ea d4 [2] fd df [2] e6 91 [2] db }

  condition:
    any of them
}