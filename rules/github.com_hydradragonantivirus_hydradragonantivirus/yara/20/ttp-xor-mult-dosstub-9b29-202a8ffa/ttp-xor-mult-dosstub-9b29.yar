rule TTP_XOR_MULT_DOSStub_9b29 {
  strings:
    $key_9b29 = { cf 41 [2] bb 59 [2] fc 5b [2] bb 4a [2] f5 46 [2] f9 4c [2] ee 47 [2] f5 09 [2] c8 }

  condition:
    any of them
}