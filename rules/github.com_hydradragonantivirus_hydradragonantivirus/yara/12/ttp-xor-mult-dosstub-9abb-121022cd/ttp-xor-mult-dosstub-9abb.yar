rule TTP_XOR_MULT_DOSStub_9abb {
  strings:
    $key_9abb = { ce d3 [2] ba cb [2] fd c9 [2] ba d8 [2] f4 d4 [2] f8 de [2] ef d5 [2] f4 9b [2] c9 }

  condition:
    any of them
}