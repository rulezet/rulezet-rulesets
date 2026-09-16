rule TTP_XOR_MULT_DOSStub_8fa2 {
  strings:
    $key_8fa2 = { db ca [2] af d2 [2] e8 d0 [2] af c1 [2] e1 cd [2] ed c7 [2] fa cc [2] e1 82 [2] dc }

  condition:
    any of them
}