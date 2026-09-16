rule TTP_XOR_MULT_DOSStub_9b77 {
  strings:
    $key_9b77 = { cf 1f [2] bb 07 [2] fc 05 [2] bb 14 [2] f5 18 [2] f9 12 [2] ee 19 [2] f5 57 [2] c8 }

  condition:
    any of them
}