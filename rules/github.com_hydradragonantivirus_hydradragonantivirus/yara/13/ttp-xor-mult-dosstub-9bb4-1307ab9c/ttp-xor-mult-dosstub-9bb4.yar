rule TTP_XOR_MULT_DOSStub_9bb4 {
  strings:
    $key_9bb4 = { cf dc [2] bb c4 [2] fc c6 [2] bb d7 [2] f5 db [2] f9 d1 [2] ee da [2] f5 94 [2] c8 }

  condition:
    any of them
}