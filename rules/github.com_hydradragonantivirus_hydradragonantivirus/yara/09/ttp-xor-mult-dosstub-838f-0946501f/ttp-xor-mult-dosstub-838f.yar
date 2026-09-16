rule TTP_XOR_MULT_DOSStub_838f {
  strings:
    $key_838f = { d7 e7 [2] a3 ff [2] e4 fd [2] a3 ec [2] ed e0 [2] e1 ea [2] f6 e1 [2] ed af [2] d0 }

  condition:
    any of them
}