rule TTP_XOR_MULT_DOSStub_9b62 {
  strings:
    $key_9b62 = { cf 0a [2] bb 12 [2] fc 10 [2] bb 01 [2] f5 0d [2] f9 07 [2] ee 0c [2] f5 42 [2] c8 }

  condition:
    any of them
}