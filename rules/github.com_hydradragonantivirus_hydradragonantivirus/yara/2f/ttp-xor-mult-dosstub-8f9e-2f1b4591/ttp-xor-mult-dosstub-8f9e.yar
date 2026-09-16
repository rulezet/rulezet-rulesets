rule TTP_XOR_MULT_DOSStub_8f9e {
  strings:
    $key_8f9e = { db f6 [2] af ee [2] e8 ec [2] af fd [2] e1 f1 [2] ed fb [2] fa f0 [2] e1 be [2] dc }

  condition:
    any of them
}