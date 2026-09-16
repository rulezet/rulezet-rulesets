rule TTP_XOR_MULT_DOSStub_9b57 {
  strings:
    $key_9b57 = { cf 3f [2] bb 27 [2] fc 25 [2] bb 34 [2] f5 38 [2] f9 32 [2] ee 39 [2] f5 77 [2] c8 }

  condition:
    any of them
}