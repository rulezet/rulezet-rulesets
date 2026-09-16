rule TTP_XOR_MULT_DOSStub_9b43 {
  strings:
    $key_9b43 = { cf 2b [2] bb 33 [2] fc 31 [2] bb 20 [2] f5 2c [2] f9 26 [2] ee 2d [2] f5 63 [2] c8 }

  condition:
    any of them
}