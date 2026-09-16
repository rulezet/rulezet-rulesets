rule TTP_XOR_MULT_DOSStub_98ad {
  strings:
    $key_98ad = { cc c5 [2] b8 dd [2] ff df [2] b8 ce [2] f6 c2 [2] fa c8 [2] ed c3 [2] f6 8d [2] cb }

  condition:
    any of them
}