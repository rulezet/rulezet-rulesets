rule TTP_XOR_MULT_DOSStub_858d {
  strings:
    $key_858d = { d1 e5 [2] a5 fd [2] e2 ff [2] a5 ee [2] eb e2 [2] e7 e8 [2] f0 e3 [2] eb ad [2] d6 }

  condition:
    any of them
}