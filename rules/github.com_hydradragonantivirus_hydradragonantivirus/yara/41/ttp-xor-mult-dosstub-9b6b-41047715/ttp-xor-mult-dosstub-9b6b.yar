rule TTP_XOR_MULT_DOSStub_9b6b {
  strings:
    $key_9b6b = { cf 03 [2] bb 1b [2] fc 19 [2] bb 08 [2] f5 04 [2] f9 0e [2] ee 05 [2] f5 4b [2] c8 }

  condition:
    any of them
}