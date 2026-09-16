rule TTP_XOR_MULT_DOSStub_9ac1 {
  strings:
    $key_9ac1 = { ce a9 [2] ba b1 [2] fd b3 [2] ba a2 [2] f4 ae [2] f8 a4 [2] ef af [2] f4 e1 [2] c9 }

  condition:
    any of them
}