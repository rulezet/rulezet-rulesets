rule TTP_XOR_MULT_DOSStub_9b17 {
  strings:
    $key_9b17 = { cf 7f [2] bb 67 [2] fc 65 [2] bb 74 [2] f5 78 [2] f9 72 [2] ee 79 [2] f5 37 [2] c8 }

  condition:
    any of them
}