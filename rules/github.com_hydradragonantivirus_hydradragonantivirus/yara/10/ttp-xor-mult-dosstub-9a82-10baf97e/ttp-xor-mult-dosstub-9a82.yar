rule TTP_XOR_MULT_DOSStub_9a82 {
  strings:
    $key_9a82 = { ce ea [2] ba f2 [2] fd f0 [2] ba e1 [2] f4 ed [2] f8 e7 [2] ef ec [2] f4 a2 [2] c9 }

  condition:
    any of them
}