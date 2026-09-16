rule TTP_XOR_MULT_DOSStub_a28f {
  strings:
    $key_a28f = { f6 e7 [2] 82 ff [2] c5 fd [2] 82 ec [2] cc e0 [2] c0 ea [2] d7 e1 [2] cc af [2] f1 }

  condition:
    any of them
}