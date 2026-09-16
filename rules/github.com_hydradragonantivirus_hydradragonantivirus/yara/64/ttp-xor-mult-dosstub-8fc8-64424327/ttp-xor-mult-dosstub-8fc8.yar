rule TTP_XOR_MULT_DOSStub_8fc8 {
  strings:
    $key_8fc8 = { db a0 [2] af b8 [2] e8 ba [2] af ab [2] e1 a7 [2] ed ad [2] fa a6 [2] e1 e8 [2] dc }

  condition:
    any of them
}