rule TTP_XOR_MULT_DOSStub_8fb6 {
  strings:
    $key_8fb6 = { db de [2] af c6 [2] e8 c4 [2] af d5 [2] e1 d9 [2] ed d3 [2] fa d8 [2] e1 96 [2] dc }

  condition:
    any of them
}