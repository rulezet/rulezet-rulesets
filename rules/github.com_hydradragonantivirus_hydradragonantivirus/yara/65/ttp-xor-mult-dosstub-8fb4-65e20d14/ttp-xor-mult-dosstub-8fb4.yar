rule TTP_XOR_MULT_DOSStub_8fb4 {
  strings:
    $key_8fb4 = { db dc [2] af c4 [2] e8 c6 [2] af d7 [2] e1 db [2] ed d1 [2] fa da [2] e1 94 [2] dc }

  condition:
    any of them
}