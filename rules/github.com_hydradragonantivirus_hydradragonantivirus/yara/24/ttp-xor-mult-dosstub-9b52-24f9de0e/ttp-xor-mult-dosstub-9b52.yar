rule TTP_XOR_MULT_DOSStub_9b52 {
  strings:
    $key_9b52 = { cf 3a [2] bb 22 [2] fc 20 [2] bb 31 [2] f5 3d [2] f9 37 [2] ee 3c [2] f5 72 [2] c8 }

  condition:
    any of them
}