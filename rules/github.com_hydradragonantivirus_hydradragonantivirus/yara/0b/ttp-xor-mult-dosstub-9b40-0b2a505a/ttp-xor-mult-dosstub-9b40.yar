rule TTP_XOR_MULT_DOSStub_9b40 {
  strings:
    $key_9b40 = { cf 28 [2] bb 30 [2] fc 32 [2] bb 23 [2] f5 2f [2] f9 25 [2] ee 2e [2] f5 60 [2] c8 }

  condition:
    any of them
}