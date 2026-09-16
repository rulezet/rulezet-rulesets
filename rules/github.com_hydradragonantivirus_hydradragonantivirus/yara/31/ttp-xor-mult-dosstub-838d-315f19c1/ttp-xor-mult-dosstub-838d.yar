rule TTP_XOR_MULT_DOSStub_838d {
  strings:
    $key_838d = { d7 e5 [2] a3 fd [2] e4 ff [2] a3 ee [2] ed e2 [2] e1 e8 [2] f6 e3 [2] ed ad [2] d0 }

  condition:
    any of them
}