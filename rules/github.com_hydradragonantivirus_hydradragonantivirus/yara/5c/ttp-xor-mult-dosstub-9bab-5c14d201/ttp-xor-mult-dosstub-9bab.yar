rule TTP_XOR_MULT_DOSStub_9bab {
  strings:
    $key_9bab = { cf c3 [2] bb db [2] fc d9 [2] bb c8 [2] f5 c4 [2] f9 ce [2] ee c5 [2] f5 8b [2] c8 }

  condition:
    any of them
}