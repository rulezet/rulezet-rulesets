rule TTP_XOR_MULT_DOSStub_98b3 {
  strings:
    $key_98b3 = { cc db [2] b8 c3 [2] ff c1 [2] b8 d0 [2] f6 dc [2] fa d6 [2] ed dd [2] f6 93 [2] cb }

  condition:
    any of them
}