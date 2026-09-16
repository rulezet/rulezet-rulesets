rule TTP_XOR_MULT_DOSStub_9b59 {
  strings:
    $key_9b59 = { cf 31 [2] bb 29 [2] fc 2b [2] bb 3a [2] f5 36 [2] f9 3c [2] ee 37 [2] f5 79 [2] c8 }

  condition:
    any of them
}