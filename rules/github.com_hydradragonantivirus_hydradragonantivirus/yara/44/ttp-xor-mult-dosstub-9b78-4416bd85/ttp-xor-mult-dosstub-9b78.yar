rule TTP_XOR_MULT_DOSStub_9b78 {
  strings:
    $key_9b78 = { cf 10 [2] bb 08 [2] fc 0a [2] bb 1b [2] f5 17 [2] f9 1d [2] ee 16 [2] f5 58 [2] c8 }

  condition:
    any of them
}