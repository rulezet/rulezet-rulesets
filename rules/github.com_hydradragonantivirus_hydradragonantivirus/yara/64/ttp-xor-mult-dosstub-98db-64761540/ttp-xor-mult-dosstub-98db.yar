rule TTP_XOR_MULT_DOSStub_98db {
  strings:
    $key_98db = { cc b3 [2] b8 ab [2] ff a9 [2] b8 b8 [2] f6 b4 [2] fa be [2] ed b5 [2] f6 fb [2] cb }

  condition:
    any of them
}