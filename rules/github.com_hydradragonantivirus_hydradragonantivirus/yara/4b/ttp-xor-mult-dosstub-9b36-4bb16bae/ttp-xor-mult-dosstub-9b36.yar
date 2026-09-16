rule TTP_XOR_MULT_DOSStub_9b36 {
  strings:
    $key_9b36 = { cf 5e [2] bb 46 [2] fc 44 [2] bb 55 [2] f5 59 [2] f9 53 [2] ee 58 [2] f5 16 [2] c8 }

  condition:
    any of them
}