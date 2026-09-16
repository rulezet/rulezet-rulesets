rule TTP_XOR_MULT_DOSStub_9b13 {
  strings:
    $key_9b13 = { cf 7b [2] bb 63 [2] fc 61 [2] bb 70 [2] f5 7c [2] f9 76 [2] ee 7d [2] f5 33 [2] c8 }

  condition:
    any of them
}