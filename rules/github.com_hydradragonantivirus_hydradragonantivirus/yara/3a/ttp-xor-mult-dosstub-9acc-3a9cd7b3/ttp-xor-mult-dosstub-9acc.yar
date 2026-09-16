rule TTP_XOR_MULT_DOSStub_9acc {
  strings:
    $key_9acc = { ce a4 [2] ba bc [2] fd be [2] ba af [2] f4 a3 [2] f8 a9 [2] ef a2 [2] f4 ec [2] c9 }

  condition:
    any of them
}