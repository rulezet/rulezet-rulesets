rule TTP_XOR_MULT_DOSStub_9b2b {
  strings:
    $key_9b2b = { cf 43 [2] bb 5b [2] fc 59 [2] bb 48 [2] f5 44 [2] f9 4e [2] ee 45 [2] f5 0b [2] c8 }

  condition:
    any of them
}