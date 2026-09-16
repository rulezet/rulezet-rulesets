rule TTP_XOR_MULT_DOSStub_9b41 {
  strings:
    $key_9b41 = { cf 29 [2] bb 31 [2] fc 33 [2] bb 22 [2] f5 2e [2] f9 24 [2] ee 2f [2] f5 61 [2] c8 }

  condition:
    any of them
}