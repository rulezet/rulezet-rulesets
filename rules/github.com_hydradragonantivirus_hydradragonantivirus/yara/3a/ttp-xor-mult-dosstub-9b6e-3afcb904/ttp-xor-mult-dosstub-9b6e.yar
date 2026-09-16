rule TTP_XOR_MULT_DOSStub_9b6e {
  strings:
    $key_9b6e = { cf 06 [2] bb 1e [2] fc 1c [2] bb 0d [2] f5 01 [2] f9 0b [2] ee 00 [2] f5 4e [2] c8 }

  condition:
    any of them
}