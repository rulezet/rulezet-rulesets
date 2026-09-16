rule TTP_XOR_MULT_DOSStub_8fd0 {
  strings:
    $key_8fd0 = { db b8 [2] af a0 [2] e8 a2 [2] af b3 [2] e1 bf [2] ed b5 [2] fa be [2] e1 f0 [2] dc }

  condition:
    any of them
}