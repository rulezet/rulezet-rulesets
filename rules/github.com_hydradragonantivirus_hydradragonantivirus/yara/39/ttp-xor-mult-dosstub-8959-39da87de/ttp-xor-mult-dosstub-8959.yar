rule TTP_XOR_MULT_DOSStub_8959 {
  strings:
    $key_8959 = { dd 31 [2] a9 29 [2] ee 2b [2] a9 3a [2] e7 36 [2] eb 3c [2] fc 37 [2] e7 79 [2] da }

  condition:
    any of them
}