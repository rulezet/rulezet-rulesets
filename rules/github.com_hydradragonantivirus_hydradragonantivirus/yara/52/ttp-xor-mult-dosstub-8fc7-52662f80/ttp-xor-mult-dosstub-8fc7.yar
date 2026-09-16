rule TTP_XOR_MULT_DOSStub_8fc7 {
  strings:
    $key_8fc7 = { db af [2] af b7 [2] e8 b5 [2] af a4 [2] e1 a8 [2] ed a2 [2] fa a9 [2] e1 e7 [2] dc }

  condition:
    any of them
}