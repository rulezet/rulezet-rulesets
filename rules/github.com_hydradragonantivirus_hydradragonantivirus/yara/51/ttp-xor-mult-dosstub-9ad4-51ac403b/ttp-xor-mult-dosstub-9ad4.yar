rule TTP_XOR_MULT_DOSStub_9ad4 {
  strings:
    $key_9ad4 = { ce bc [2] ba a4 [2] fd a6 [2] ba b7 [2] f4 bb [2] f8 b1 [2] ef ba [2] f4 f4 [2] c9 }

  condition:
    any of them
}