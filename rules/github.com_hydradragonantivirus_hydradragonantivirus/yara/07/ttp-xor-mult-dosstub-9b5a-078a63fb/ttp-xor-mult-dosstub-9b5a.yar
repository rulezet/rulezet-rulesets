rule TTP_XOR_MULT_DOSStub_9b5a {
  strings:
    $key_9b5a = { cf 32 [2] bb 2a [2] fc 28 [2] bb 39 [2] f5 35 [2] f9 3f [2] ee 34 [2] f5 7a [2] c8 }

  condition:
    any of them
}