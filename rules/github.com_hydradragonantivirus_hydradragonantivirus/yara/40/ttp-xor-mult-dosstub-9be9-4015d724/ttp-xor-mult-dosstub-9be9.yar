rule TTP_XOR_MULT_DOSStub_9be9 {
  strings:
    $key_9be9 = { cf 81 [2] bb 99 [2] fc 9b [2] bb 8a [2] f5 86 [2] f9 8c [2] ee 87 [2] f5 c9 [2] c8 }

  condition:
    any of them
}