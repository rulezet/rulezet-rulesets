rule TTP_XOR_MULT_DOSStub_9bf0 {
  strings:
    $key_9bf0 = { cf 98 [2] bb 80 [2] fc 82 [2] bb 93 [2] f5 9f [2] f9 95 [2] ee 9e [2] f5 d0 [2] c8 }

  condition:
    any of them
}