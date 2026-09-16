rule TTP_XOR_MULT_DOSStub_9be5 {
  strings:
    $key_9be5 = { cf 8d [2] bb 95 [2] fc 97 [2] bb 86 [2] f5 8a [2] f9 80 [2] ee 8b [2] f5 c5 [2] c8 }

  condition:
    any of them
}