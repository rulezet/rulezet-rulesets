rule TTP_XOR_MULT_DOSStub_9ba6 {
  strings:
    $key_9ba6 = { cf ce [2] bb d6 [2] fc d4 [2] bb c5 [2] f5 c9 [2] f9 c3 [2] ee c8 [2] f5 86 [2] c8 }

  condition:
    any of them
}