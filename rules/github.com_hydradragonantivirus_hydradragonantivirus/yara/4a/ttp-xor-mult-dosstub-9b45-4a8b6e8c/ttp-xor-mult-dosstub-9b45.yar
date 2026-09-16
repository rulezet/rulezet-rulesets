rule TTP_XOR_MULT_DOSStub_9b45 {
  strings:
    $key_9b45 = { cf 2d [2] bb 35 [2] fc 37 [2] bb 26 [2] f5 2a [2] f9 20 [2] ee 2b [2] f5 65 [2] c8 }

  condition:
    any of them
}