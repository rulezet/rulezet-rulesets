rule TTP_XOR_MULT_DOSStub_9a9c {
  strings:
    $key_9a9c = { ce f4 [2] ba ec [2] fd ee [2] ba ff [2] f4 f3 [2] f8 f9 [2] ef f2 [2] f4 bc [2] c9 }

  condition:
    any of them
}