rule TTP_XOR_MULT_DOSStub_8b9a {
  strings:
    $key_8b9a = { df f2 [2] ab ea [2] ec e8 [2] ab f9 [2] e5 f5 [2] e9 ff [2] fe f4 [2] e5 ba [2] d8 }

  condition:
    any of them
}