rule TTP_XOR_MULT_DOSStub_9b37 {
  strings:
    $key_9b37 = { cf 5f [2] bb 47 [2] fc 45 [2] bb 54 [2] f5 58 [2] f9 52 [2] ee 59 [2] f5 17 [2] c8 }

  condition:
    any of them
}