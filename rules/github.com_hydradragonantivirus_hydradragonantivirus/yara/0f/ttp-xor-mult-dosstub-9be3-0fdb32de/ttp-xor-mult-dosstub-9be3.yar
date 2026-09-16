rule TTP_XOR_MULT_DOSStub_9be3 {
  strings:
    $key_9be3 = { cf 8b [2] bb 93 [2] fc 91 [2] bb 80 [2] f5 8c [2] f9 86 [2] ee 8d [2] f5 c3 [2] c8 }

  condition:
    any of them
}