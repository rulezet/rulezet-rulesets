rule TTP_XOR_MULT_DOSStub_889e {
  strings:
    $key_889e = { dc f6 [2] a8 ee [2] ef ec [2] a8 fd [2] e6 f1 [2] ea fb [2] fd f0 [2] e6 be [2] db }

  condition:
    any of them
}