rule TTP_XOR_MULT_DOSStub_9b1a {
  strings:
    $key_9b1a = { cf 72 [2] bb 6a [2] fc 68 [2] bb 79 [2] f5 75 [2] f9 7f [2] ee 74 [2] f5 3a [2] c8 }

  condition:
    any of them
}