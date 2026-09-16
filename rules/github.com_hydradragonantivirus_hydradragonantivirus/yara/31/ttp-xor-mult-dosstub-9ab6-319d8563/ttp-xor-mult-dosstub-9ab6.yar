rule TTP_XOR_MULT_DOSStub_9ab6 {
  strings:
    $key_9ab6 = { ce de [2] ba c6 [2] fd c4 [2] ba d5 [2] f4 d9 [2] f8 d3 [2] ef d8 [2] f4 96 [2] c9 }

  condition:
    any of them
}