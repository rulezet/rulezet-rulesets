rule TTP_XOR_MULT_DOSStub_a48f {
  strings:
    $key_a48f = { f0 e7 [2] 84 ff [2] c3 fd [2] 84 ec [2] ca e0 [2] c6 ea [2] d1 e1 [2] ca af [2] f7 }

  condition:
    any of them
}