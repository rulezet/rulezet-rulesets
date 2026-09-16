rule TTP_XOR_MULT_DOSStub_888d {
  strings:
    $key_888d = { dc e5 [2] a8 fd [2] ef ff [2] a8 ee [2] e6 e2 [2] ea e8 [2] fd e3 [2] e6 ad [2] db }

  condition:
    any of them
}