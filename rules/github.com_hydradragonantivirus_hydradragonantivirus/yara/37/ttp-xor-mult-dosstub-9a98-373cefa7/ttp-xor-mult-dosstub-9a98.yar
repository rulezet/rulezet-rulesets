rule TTP_XOR_MULT_DOSStub_9a98 {
  strings:
    $key_9a98 = { ce f0 [2] ba e8 [2] fd ea [2] ba fb [2] f4 f7 [2] f8 fd [2] ef f6 [2] f4 b8 [2] c9 }

  condition:
    any of them
}