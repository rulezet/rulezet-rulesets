rule TTP_XOR_MULT_DOSStub_988f {
  strings:
    $key_988f = { cc e7 [2] b8 ff [2] ff fd [2] b8 ec [2] f6 e0 [2] fa ea [2] ed e1 [2] f6 af [2] cb }

  condition:
    any of them
}