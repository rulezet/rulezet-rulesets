rule TTP_XOR_MULT_DOSStub_9be0 {
  strings:
    $key_9be0 = { cf 88 [2] bb 90 [2] fc 92 [2] bb 83 [2] f5 8f [2] f9 85 [2] ee 8e [2] f5 c0 [2] c8 }

  condition:
    any of them
}