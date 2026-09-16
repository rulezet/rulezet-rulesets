rule TTP_XOR_MULT_DOSStub_9ace {
  strings:
    $key_9ace = { ce a6 [2] ba be [2] fd bc [2] ba ad [2] f4 a1 [2] f8 ab [2] ef a0 [2] f4 ee [2] c9 }

  condition:
    any of them
}