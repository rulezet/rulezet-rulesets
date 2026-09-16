rule TTP_XOR_MULT_DOSStub_8fd5 {
  strings:
    $key_8fd5 = { db bd [2] af a5 [2] e8 a7 [2] af b6 [2] e1 ba [2] ed b0 [2] fa bb [2] e1 f5 [2] dc }

  condition:
    any of them
}