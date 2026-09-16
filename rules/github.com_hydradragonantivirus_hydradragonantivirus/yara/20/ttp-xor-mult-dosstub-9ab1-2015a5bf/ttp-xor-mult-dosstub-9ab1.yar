rule TTP_XOR_MULT_DOSStub_9ab1 {
  strings:
    $key_9ab1 = { ce d9 [2] ba c1 [2] fd c3 [2] ba d2 [2] f4 de [2] f8 d4 [2] ef df [2] f4 91 [2] c9 }

  condition:
    any of them
}