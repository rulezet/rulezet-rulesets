rule TTP_XOR_MULT_DOSStub_9b79 {
  strings:
    $key_9b79 = { cf 11 [2] bb 09 [2] fc 0b [2] bb 1a [2] f5 16 [2] f9 1c [2] ee 17 [2] f5 59 [2] c8 }

  condition:
    any of them
}