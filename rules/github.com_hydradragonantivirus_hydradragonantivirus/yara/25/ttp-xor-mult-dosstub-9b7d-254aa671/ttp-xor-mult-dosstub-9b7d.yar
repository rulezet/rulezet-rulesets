rule TTP_XOR_MULT_DOSStub_9b7d {
  strings:
    $key_9b7d = { cf 15 [2] bb 0d [2] fc 0f [2] bb 1e [2] f5 12 [2] f9 18 [2] ee 13 [2] f5 5d [2] c8 }

  condition:
    any of them
}