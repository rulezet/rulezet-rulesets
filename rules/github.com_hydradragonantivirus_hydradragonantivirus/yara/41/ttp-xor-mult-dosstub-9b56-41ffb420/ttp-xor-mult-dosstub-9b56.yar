rule TTP_XOR_MULT_DOSStub_9b56 {
  strings:
    $key_9b56 = { cf 3e [2] bb 26 [2] fc 24 [2] bb 35 [2] f5 39 [2] f9 33 [2] ee 38 [2] f5 76 [2] c8 }

  condition:
    any of them
}