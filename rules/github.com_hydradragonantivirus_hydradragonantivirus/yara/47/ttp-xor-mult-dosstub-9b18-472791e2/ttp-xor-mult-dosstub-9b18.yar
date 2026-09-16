rule TTP_XOR_MULT_DOSStub_9b18 {
  strings:
    $key_9b18 = { cf 70 [2] bb 68 [2] fc 6a [2] bb 7b [2] f5 77 [2] f9 7d [2] ee 76 [2] f5 38 [2] c8 }

  condition:
    any of them
}