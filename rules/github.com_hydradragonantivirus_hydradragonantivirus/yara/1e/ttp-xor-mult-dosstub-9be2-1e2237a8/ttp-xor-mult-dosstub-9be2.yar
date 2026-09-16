rule TTP_XOR_MULT_DOSStub_9be2 {
  strings:
    $key_9be2 = { cf 8a [2] bb 92 [2] fc 90 [2] bb 81 [2] f5 8d [2] f9 87 [2] ee 8c [2] f5 c2 [2] c8 }

  condition:
    any of them
}