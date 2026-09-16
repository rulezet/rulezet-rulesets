rule TTP_XOR_MULT_DOSStub_9b06 {
  strings:
    $key_9b06 = { cf 6e [2] bb 76 [2] fc 74 [2] bb 65 [2] f5 69 [2] f9 63 [2] ee 68 [2] f5 26 [2] c8 }

  condition:
    any of them
}