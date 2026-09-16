rule TTP_XOR_MULT_DOSStub_9ab9 {
  strings:
    $key_9ab9 = { ce d1 [2] ba c9 [2] fd cb [2] ba da [2] f4 d6 [2] f8 dc [2] ef d7 [2] f4 99 [2] c9 }

  condition:
    any of them
}