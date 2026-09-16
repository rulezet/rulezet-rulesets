rule TTP_XOR_MULT_DOSStub_8fab {
  strings:
    $key_8fab = { db c3 [2] af db [2] e8 d9 [2] af c8 [2] e1 c4 [2] ed ce [2] fa c5 [2] e1 8b [2] dc }

  condition:
    any of them
}