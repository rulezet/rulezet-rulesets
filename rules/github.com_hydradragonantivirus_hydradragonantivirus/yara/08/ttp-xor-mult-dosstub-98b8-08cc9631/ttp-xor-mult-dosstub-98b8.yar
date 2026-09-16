rule TTP_XOR_MULT_DOSStub_98b8 {
  strings:
    $key_98b8 = { cc d0 [2] b8 c8 [2] ff ca [2] b8 db [2] f6 d7 [2] fa dd [2] ed d6 [2] f6 98 [2] cb }

  condition:
    any of them
}