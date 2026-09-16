rule TTP_XOR_MULT_DOSStub_9ac8 {
  strings:
    $key_9ac8 = { ce a0 [2] ba b8 [2] fd ba [2] ba ab [2] f4 a7 [2] f8 ad [2] ef a6 [2] f4 e8 [2] c9 }

  condition:
    any of them
}