rule TTP_XOR_MULT_DOSStub_9a86 {
  strings:
    $key_9a86 = { ce ee [2] ba f6 [2] fd f4 [2] ba e5 [2] f4 e9 [2] f8 e3 [2] ef e8 [2] f4 a6 [2] c9 }

  condition:
    any of them
}