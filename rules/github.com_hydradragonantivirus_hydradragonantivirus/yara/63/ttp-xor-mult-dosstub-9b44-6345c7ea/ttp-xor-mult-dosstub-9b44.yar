rule TTP_XOR_MULT_DOSStub_9b44 {
  strings:
    $key_9b44 = { cf 2c [2] bb 34 [2] fc 36 [2] bb 27 [2] f5 2b [2] f9 21 [2] ee 2a [2] f5 64 [2] c8 }

  condition:
    any of them
}