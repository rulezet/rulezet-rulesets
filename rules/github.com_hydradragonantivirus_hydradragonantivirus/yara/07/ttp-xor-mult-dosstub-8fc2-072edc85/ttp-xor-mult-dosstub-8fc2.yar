rule TTP_XOR_MULT_DOSStub_8fc2 {
  strings:
    $key_8fc2 = { db aa [2] af b2 [2] e8 b0 [2] af a1 [2] e1 ad [2] ed a7 [2] fa ac [2] e1 e2 [2] dc }

  condition:
    any of them
}