rule TTP_XOR_MULT_DOSStub_8b91 {
  strings:
    $key_8b91 = { df f9 [2] ab e1 [2] ec e3 [2] ab f2 [2] e5 fe [2] e9 f4 [2] fe ff [2] e5 b1 [2] d8 }

  condition:
    any of them
}