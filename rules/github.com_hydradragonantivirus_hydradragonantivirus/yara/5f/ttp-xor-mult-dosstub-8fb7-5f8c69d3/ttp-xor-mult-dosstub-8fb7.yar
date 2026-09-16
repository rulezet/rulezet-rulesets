rule TTP_XOR_MULT_DOSStub_8fb7 {
  strings:
    $key_8fb7 = { db df [2] af c7 [2] e8 c5 [2] af d4 [2] e1 d8 [2] ed d2 [2] fa d9 [2] e1 97 [2] dc }

  condition:
    any of them
}