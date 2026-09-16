rule TTP_XOR_MULT_DOSStub_9b11 {
  strings:
    $key_9b11 = { cf 79 [2] bb 61 [2] fc 63 [2] bb 72 [2] f5 7e [2] f9 74 [2] ee 7f [2] f5 31 [2] c8 }

  condition:
    any of them
}