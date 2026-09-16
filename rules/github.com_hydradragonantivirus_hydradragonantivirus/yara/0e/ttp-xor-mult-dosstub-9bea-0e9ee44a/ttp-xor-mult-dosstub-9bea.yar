rule TTP_XOR_MULT_DOSStub_9bea {
  strings:
    $key_9bea = { cf 82 [2] bb 9a [2] fc 98 [2] bb 89 [2] f5 85 [2] f9 8f [2] ee 84 [2] f5 ca [2] c8 }

  condition:
    any of them
}