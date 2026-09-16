rule TTP_XOR_MULT_DOSStub_9b2a {
  strings:
    $key_9b2a = { cf 42 [2] bb 5a [2] fc 58 [2] bb 49 [2] f5 45 [2] f9 4f [2] ee 44 [2] f5 0a [2] c8 }

  condition:
    any of them
}