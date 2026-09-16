rule TTP_XOR_MULT_DOSStub_9ba9 {
  strings:
    $key_9ba9 = { cf c1 [2] bb d9 [2] fc db [2] bb ca [2] f5 c6 [2] f9 cc [2] ee c7 [2] f5 89 [2] c8 }

  condition:
    any of them
}