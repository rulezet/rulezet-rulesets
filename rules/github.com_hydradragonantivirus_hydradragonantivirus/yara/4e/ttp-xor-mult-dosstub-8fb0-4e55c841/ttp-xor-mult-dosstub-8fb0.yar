rule TTP_XOR_MULT_DOSStub_8fb0 {
  strings:
    $key_8fb0 = { db d8 [2] af c0 [2] e8 c2 [2] af d3 [2] e1 df [2] ed d5 [2] fa de [2] e1 90 [2] dc }

  condition:
    any of them
}