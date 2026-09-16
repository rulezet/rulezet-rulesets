rule TTP_XOR_MULT_DOSStub_8928 {
  strings:
    $key_8928 = { dd 40 [2] a9 58 [2] ee 5a [2] a9 4b [2] e7 47 [2] eb 4d [2] fc 46 [2] e7 08 [2] da }

  condition:
    any of them
}