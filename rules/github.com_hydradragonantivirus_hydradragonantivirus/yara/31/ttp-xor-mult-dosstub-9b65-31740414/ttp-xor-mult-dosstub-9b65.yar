rule TTP_XOR_MULT_DOSStub_9b65 {
  strings:
    $key_9b65 = { cf 0d [2] bb 15 [2] fc 17 [2] bb 06 [2] f5 0a [2] f9 00 [2] ee 0b [2] f5 45 [2] c8 }

  condition:
    any of them
}