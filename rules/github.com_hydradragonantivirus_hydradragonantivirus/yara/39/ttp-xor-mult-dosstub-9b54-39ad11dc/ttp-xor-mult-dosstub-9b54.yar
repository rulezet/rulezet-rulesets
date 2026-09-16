rule TTP_XOR_MULT_DOSStub_9b54 {
  strings:
    $key_9b54 = { cf 3c [2] bb 24 [2] fc 26 [2] bb 37 [2] f5 3b [2] f9 31 [2] ee 3a [2] f5 74 [2] c8 }

  condition:
    any of them
}