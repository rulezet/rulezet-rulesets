rule TTP_XOR_MULT_DOSStub_cf9e {
  strings:
    $key_cf9e = { 9b f6 [2] ef ee [2] a8 ec [2] ef fd [2] a1 f1 [2] ad fb [2] ba f0 [2] a1 be [2] 9c }

  condition:
    any of them
}