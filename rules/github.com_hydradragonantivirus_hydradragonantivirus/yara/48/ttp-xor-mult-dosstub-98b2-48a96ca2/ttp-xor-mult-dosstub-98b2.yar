rule TTP_XOR_MULT_DOSStub_98b2 {
  strings:
    $key_98b2 = { cc da [2] b8 c2 [2] ff c0 [2] b8 d1 [2] f6 dd [2] fa d7 [2] ed dc [2] f6 92 [2] cb }

  condition:
    any of them
}