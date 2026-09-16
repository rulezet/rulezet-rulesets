rule TTP_XOR_MULT_DOSStub_9bb6 {
  strings:
    $key_9bb6 = { cf de [2] bb c6 [2] fc c4 [2] bb d5 [2] f5 d9 [2] f9 d3 [2] ee d8 [2] f5 96 [2] c8 }

  condition:
    any of them
}