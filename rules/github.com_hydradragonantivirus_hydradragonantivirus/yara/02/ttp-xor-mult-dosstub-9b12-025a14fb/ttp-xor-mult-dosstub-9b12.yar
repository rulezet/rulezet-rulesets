rule TTP_XOR_MULT_DOSStub_9b12 {
  strings:
    $key_9b12 = { cf 7a [2] bb 62 [2] fc 60 [2] bb 71 [2] f5 7d [2] f9 77 [2] ee 7c [2] f5 32 [2] c8 }

  condition:
    any of them
}