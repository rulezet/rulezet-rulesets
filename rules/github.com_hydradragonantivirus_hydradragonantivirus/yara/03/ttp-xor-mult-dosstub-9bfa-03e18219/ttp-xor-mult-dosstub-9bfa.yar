rule TTP_XOR_MULT_DOSStub_9bfa {
  strings:
    $key_9bfa = { cf 92 [2] bb 8a [2] fc 88 [2] bb 99 [2] f5 95 [2] f9 9f [2] ee 94 [2] f5 da [2] c8 }

  condition:
    any of them
}