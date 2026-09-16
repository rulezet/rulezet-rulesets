rule TTP_XOR_MULT_DOSStub_9b42 {
  strings:
    $key_9b42 = { cf 2a [2] bb 32 [2] fc 30 [2] bb 21 [2] f5 2d [2] f9 27 [2] ee 2c [2] f5 62 [2] c8 }

  condition:
    any of them
}