rule TTP_XOR_MULT_DOSStub_9b10 {
  strings:
    $key_9b10 = { cf 78 [2] bb 60 [2] fc 62 [2] bb 73 [2] f5 7f [2] f9 75 [2] ee 7e [2] f5 30 [2] c8 }

  condition:
    any of them
}