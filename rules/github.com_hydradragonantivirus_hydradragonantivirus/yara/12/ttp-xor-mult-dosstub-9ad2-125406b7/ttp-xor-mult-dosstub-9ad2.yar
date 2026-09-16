rule TTP_XOR_MULT_DOSStub_9ad2 {
  strings:
    $key_9ad2 = { ce ba [2] ba a2 [2] fd a0 [2] ba b1 [2] f4 bd [2] f8 b7 [2] ef bc [2] f4 f2 [2] c9 }

  condition:
    any of them
}