rule TTP_XOR_MULT_DOSStub_958f {
  strings:
    $key_958f = { c1 e7 [2] b5 ff [2] f2 fd [2] b5 ec [2] fb e0 [2] f7 ea [2] e0 e1 [2] fb af [2] c6 }

  condition:
    any of them
}