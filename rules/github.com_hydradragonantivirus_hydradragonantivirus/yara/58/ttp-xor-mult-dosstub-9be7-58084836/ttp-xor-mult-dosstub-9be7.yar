rule TTP_XOR_MULT_DOSStub_9be7 {
  strings:
    $key_9be7 = { cf 8f [2] bb 97 [2] fc 95 [2] bb 84 [2] f5 88 [2] f9 82 [2] ee 89 [2] f5 c7 [2] c8 }

  condition:
    any of them
}