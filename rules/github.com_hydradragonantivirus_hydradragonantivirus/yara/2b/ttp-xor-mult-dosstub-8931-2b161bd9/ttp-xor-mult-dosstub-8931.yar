rule TTP_XOR_MULT_DOSStub_8931 {
  strings:
    $key_8931 = { dd 59 [2] a9 41 [2] ee 43 [2] a9 52 [2] e7 5e [2] eb 54 [2] fc 5f [2] e7 11 [2] da }

  condition:
    any of them
}