rule TTP_XOR_MULT_DOSStub_d880 {
  strings:
    $key_d880 = { 8c e8 [2] f8 f0 [2] bf f2 [2] f8 e3 [2] b6 ef [2] ba e5 [2] ad ee [2] b6 a0 [2] 8b }

  condition:
    any of them
}