rule TTP_XOR_MULT_DOSStub_8fa4 {
  strings:
    $key_8fa4 = { db cc [2] af d4 [2] e8 d6 [2] af c7 [2] e1 cb [2] ed c1 [2] fa ca [2] e1 84 [2] dc }

  condition:
    any of them
}