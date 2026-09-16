rule TTP_XOR_MULT_DOSStub_9a80 {
  strings:
    $key_9a80 = { ce e8 [2] ba f0 [2] fd f2 [2] ba e3 [2] f4 ef [2] f8 e5 [2] ef ee [2] f4 a0 [2] c9 }

  condition:
    any of them
}