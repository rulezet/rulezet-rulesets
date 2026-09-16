rule TTP_XOR_MULT_DOSStub_98be {
  strings:
    $key_98be = { cc d6 [2] b8 ce [2] ff cc [2] b8 dd [2] f6 d1 [2] fa db [2] ed d0 [2] f6 9e [2] cb }

  condition:
    any of them
}