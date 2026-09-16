rule TTP_XOR_MULT_DOSStub_9b27 {
  strings:
    $key_9b27 = { cf 4f [2] bb 57 [2] fc 55 [2] bb 44 [2] f5 48 [2] f9 42 [2] ee 49 [2] f5 07 [2] c8 }

  condition:
    any of them
}