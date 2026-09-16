rule TTP_XOR_MULT_DOSStub_9b7c {
  strings:
    $key_9b7c = { cf 14 [2] bb 0c [2] fc 0e [2] bb 1f [2] f5 13 [2] f9 19 [2] ee 12 [2] f5 5c [2] c8 }

  condition:
    any of them
}