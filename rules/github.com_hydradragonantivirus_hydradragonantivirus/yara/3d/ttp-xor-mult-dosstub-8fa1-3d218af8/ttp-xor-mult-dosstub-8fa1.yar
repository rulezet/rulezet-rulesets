rule TTP_XOR_MULT_DOSStub_8fa1 {
  strings:
    $key_8fa1 = { db c9 [2] af d1 [2] e8 d3 [2] af c2 [2] e1 ce [2] ed c4 [2] fa cf [2] e1 81 [2] dc }

  condition:
    any of them
}