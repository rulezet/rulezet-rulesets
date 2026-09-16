rule TTP_XOR_MULT_DOSStub_9b22 {
  strings:
    $key_9b22 = { cf 4a [2] bb 52 [2] fc 50 [2] bb 41 [2] f5 4d [2] f9 47 [2] ee 4c [2] f5 02 [2] c8 }

  condition:
    any of them
}