rule TTP_XOR_MULT_DOSStub_9897 {
  strings:
    $key_9897 = { cc ff [2] b8 e7 [2] ff e5 [2] b8 f4 [2] f6 f8 [2] fa f2 [2] ed f9 [2] f6 b7 [2] cb }

  condition:
    any of them
}