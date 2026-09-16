rule TTP_XOR_MULT_DOSStub_9b01 {
  strings:
    $key_9b01 = { cf 69 [2] bb 71 [2] fc 73 [2] bb 62 [2] f5 6e [2] f9 64 [2] ee 6f [2] f5 21 [2] c8 }

  condition:
    any of them
}