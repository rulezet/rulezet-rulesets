rule TTP_XOR_MULT_DOSStub_88ca {
  strings:
    $key_88ca = { dc a2 [2] a8 ba [2] ef b8 [2] a8 a9 [2] e6 a5 [2] ea af [2] fd a4 [2] e6 ea [2] db }

  condition:
    any of them
}