rule TTP_XOR_MULT_DOSStub_8972 {
  strings:
    $key_8972 = { dd 1a [2] a9 02 [2] ee 00 [2] a9 11 [2] e7 1d [2] eb 17 [2] fc 1c [2] e7 52 [2] da }

  condition:
    any of them
}