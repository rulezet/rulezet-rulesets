rule TTP_XOR_MULT_DOSStub_9ac6 {
  strings:
    $key_9ac6 = { ce ae [2] ba b6 [2] fd b4 [2] ba a5 [2] f4 a9 [2] f8 a3 [2] ef a8 [2] f4 e6 [2] c9 }

  condition:
    any of them
}