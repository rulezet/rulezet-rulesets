rule TTP_XOR_MULT_DOSStub_9b34 {
  strings:
    $key_9b34 = { cf 5c [2] bb 44 [2] fc 46 [2] bb 57 [2] f5 5b [2] f9 51 [2] ee 5a [2] f5 14 [2] c8 }

  condition:
    any of them
}