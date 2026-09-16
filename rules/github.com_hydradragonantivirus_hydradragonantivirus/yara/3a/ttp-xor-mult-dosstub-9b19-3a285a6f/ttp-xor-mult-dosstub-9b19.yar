rule TTP_XOR_MULT_DOSStub_9b19 {
  strings:
    $key_9b19 = { cf 71 [2] bb 69 [2] fc 6b [2] bb 7a [2] f5 76 [2] f9 7c [2] ee 77 [2] f5 39 [2] c8 }

  condition:
    any of them
}