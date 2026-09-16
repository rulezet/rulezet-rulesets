rule TTP_XOR_MULT_DOSStub_9ab0 {
  strings:
    $key_9ab0 = { ce d8 [2] ba c0 [2] fd c2 [2] ba d3 [2] f4 df [2] f8 d5 [2] ef de [2] f4 90 [2] c9 }

  condition:
    any of them
}