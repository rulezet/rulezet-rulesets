rule TTP_XOR_MULT_DOSStub_8f83 {
  strings:
    $key_8f83 = { db eb [2] af f3 [2] e8 f1 [2] af e0 [2] e1 ec [2] ed e6 [2] fa ed [2] e1 a3 [2] dc }

  condition:
    any of them
}