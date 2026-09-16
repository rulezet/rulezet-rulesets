rule TTP_XOR_MULT_DOSStub_8fd4 {
  strings:
    $key_8fd4 = { db bc [2] af a4 [2] e8 a6 [2] af b7 [2] e1 bb [2] ed b1 [2] fa ba [2] e1 f4 [2] dc }

  condition:
    any of them
}