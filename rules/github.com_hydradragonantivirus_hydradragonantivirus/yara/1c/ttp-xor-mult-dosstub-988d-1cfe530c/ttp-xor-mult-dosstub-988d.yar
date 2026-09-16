rule TTP_XOR_MULT_DOSStub_988d {
  strings:
    $key_988d = { cc e5 [2] b8 fd [2] ff ff [2] b8 ee [2] f6 e2 [2] fa e8 [2] ed e3 [2] f6 ad [2] cb }

  condition:
    any of them
}