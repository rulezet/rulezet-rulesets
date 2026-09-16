rule TTP_XOR_MULT_DOSStub_8fa7 {
  strings:
    $key_8fa7 = { db cf [2] af d7 [2] e8 d5 [2] af c4 [2] e1 c8 [2] ed c2 [2] fa c9 [2] e1 87 [2] dc }

  condition:
    any of them
}