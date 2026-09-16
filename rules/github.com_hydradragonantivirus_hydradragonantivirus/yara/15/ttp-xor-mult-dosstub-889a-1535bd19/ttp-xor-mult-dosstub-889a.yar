rule TTP_XOR_MULT_DOSStub_889a {
  strings:
    $key_889a = { dc f2 [2] a8 ea [2] ef e8 [2] a8 f9 [2] e6 f5 [2] ea ff [2] fd f4 [2] e6 ba [2] db }

  condition:
    any of them
}