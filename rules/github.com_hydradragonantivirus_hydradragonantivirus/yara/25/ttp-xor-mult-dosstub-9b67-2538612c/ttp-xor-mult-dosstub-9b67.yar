rule TTP_XOR_MULT_DOSStub_9b67 {
  strings:
    $key_9b67 = { cf 0f [2] bb 17 [2] fc 15 [2] bb 04 [2] f5 08 [2] f9 02 [2] ee 09 [2] f5 47 [2] c8 }

  condition:
    any of them
}