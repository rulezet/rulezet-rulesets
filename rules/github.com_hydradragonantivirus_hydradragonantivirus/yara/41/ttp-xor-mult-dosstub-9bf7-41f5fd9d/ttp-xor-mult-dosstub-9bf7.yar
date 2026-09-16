rule TTP_XOR_MULT_DOSStub_9bf7 {
  strings:
    $key_9bf7 = { cf 9f [2] bb 87 [2] fc 85 [2] bb 94 [2] f5 98 [2] f9 92 [2] ee 99 [2] f5 d7 [2] c8 }

  condition:
    any of them
}