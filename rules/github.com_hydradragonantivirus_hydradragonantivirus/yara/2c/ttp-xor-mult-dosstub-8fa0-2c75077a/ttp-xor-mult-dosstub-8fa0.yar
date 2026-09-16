rule TTP_XOR_MULT_DOSStub_8fa0 {
  strings:
    $key_8fa0 = { db c8 [2] af d0 [2] e8 d2 [2] af c3 [2] e1 cf [2] ed c5 [2] fa ce [2] e1 80 [2] dc }

  condition:
    any of them
}