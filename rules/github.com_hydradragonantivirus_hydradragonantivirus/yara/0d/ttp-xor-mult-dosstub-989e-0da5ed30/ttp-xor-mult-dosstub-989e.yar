rule TTP_XOR_MULT_DOSStub_989e {
  strings:
    $key_989e = { cc f6 [2] b8 ee [2] ff ec [2] b8 fd [2] f6 f1 [2] fa fb [2] ed f0 [2] f6 be [2] cb }

  condition:
    any of them
}