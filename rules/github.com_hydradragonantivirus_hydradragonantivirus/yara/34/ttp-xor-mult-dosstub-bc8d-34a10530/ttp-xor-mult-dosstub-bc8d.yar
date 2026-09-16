rule TTP_XOR_MULT_DOSStub_bc8d {
  strings:
    $key_bc8d = { e8 e5 [2] 9c fd [2] db ff [2] 9c ee [2] d2 e2 [2] de e8 [2] c9 e3 [2] d2 ad [2] ef }

  condition:
    any of them
}