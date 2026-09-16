rule TTP_XOR_MULT_DOSStub_8fb9 {
  strings:
    $key_8fb9 = { db d1 [2] af c9 [2] e8 cb [2] af da [2] e1 d6 [2] ed dc [2] fa d7 [2] e1 99 [2] dc }

  condition:
    any of them
}