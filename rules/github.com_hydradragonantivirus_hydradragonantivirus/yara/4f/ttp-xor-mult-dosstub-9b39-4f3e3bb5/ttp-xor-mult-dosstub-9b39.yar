rule TTP_XOR_MULT_DOSStub_9b39 {
  strings:
    $key_9b39 = { cf 51 [2] bb 49 [2] fc 4b [2] bb 5a [2] f5 56 [2] f9 5c [2] ee 57 [2] f5 19 [2] c8 }

  condition:
    any of them
}