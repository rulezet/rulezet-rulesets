rule TTP_XOR_MULT_DOSStub_9a84 {
  strings:
    $key_9a84 = { ce ec [2] ba f4 [2] fd f6 [2] ba e7 [2] f4 eb [2] f8 e1 [2] ef ea [2] f4 a4 [2] c9 }

  condition:
    any of them
}