rule TTP_XOR_MULT_DOSStub_9b7b {
  strings:
    $key_9b7b = { cf 13 [2] bb 0b [2] fc 09 [2] bb 18 [2] f5 14 [2] f9 1e [2] ee 15 [2] f5 5b [2] c8 }

  condition:
    any of them
}