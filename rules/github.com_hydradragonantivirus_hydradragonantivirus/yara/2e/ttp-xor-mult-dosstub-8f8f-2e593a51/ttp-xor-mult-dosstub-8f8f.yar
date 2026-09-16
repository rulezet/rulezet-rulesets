rule TTP_XOR_MULT_DOSStub_8f8f {
  strings:
    $key_8f8f = { db e7 [2] af ff [2] e8 fd [2] af ec [2] e1 e0 [2] ed ea [2] fa e1 [2] e1 af [2] dc }

  condition:
    any of them
}