rule TTP_XOR_MULT_DOSStub_9b31 {
  strings:
    $key_9b31 = { cf 59 [2] bb 41 [2] fc 43 [2] bb 52 [2] f5 5e [2] f9 54 [2] ee 5f [2] f5 11 [2] c8 }

  condition:
    any of them
}