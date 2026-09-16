rule TTP_XOR_MULT_DOSStub_9b30 {
  strings:
    $key_9b30 = { cf 58 [2] bb 40 [2] fc 42 [2] bb 53 [2] f5 5f [2] f9 55 [2] ee 5e [2] f5 10 [2] c8 }

  condition:
    any of them
}