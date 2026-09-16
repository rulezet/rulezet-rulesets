rule TTP_XOR_MULT_DOSStub_9b0b {
  strings:
    $key_9b0b = { cf 63 [2] bb 7b [2] fc 79 [2] bb 68 [2] f5 64 [2] f9 6e [2] ee 65 [2] f5 2b [2] c8 }

  condition:
    any of them
}