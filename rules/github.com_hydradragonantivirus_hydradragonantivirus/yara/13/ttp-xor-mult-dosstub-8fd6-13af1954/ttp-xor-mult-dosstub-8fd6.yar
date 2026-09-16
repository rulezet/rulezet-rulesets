rule TTP_XOR_MULT_DOSStub_8fd6 {
  strings:
    $key_8fd6 = { db be [2] af a6 [2] e8 a4 [2] af b5 [2] e1 b9 [2] ed b3 [2] fa b8 [2] e1 f6 [2] dc }

  condition:
    any of them
}