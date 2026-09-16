rule TTP_XOR_MULT_DOSStub_8fc0 {
  strings:
    $key_8fc0 = { db a8 [2] af b0 [2] e8 b2 [2] af a3 [2] e1 af [2] ed a5 [2] fa ae [2] e1 e0 [2] dc }

  condition:
    any of them
}