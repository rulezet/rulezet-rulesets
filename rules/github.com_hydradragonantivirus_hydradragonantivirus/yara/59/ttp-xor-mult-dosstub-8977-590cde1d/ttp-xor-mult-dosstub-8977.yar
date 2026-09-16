rule TTP_XOR_MULT_DOSStub_8977 {
  strings:
    $key_8977 = { dd 1f [2] a9 07 [2] ee 05 [2] a9 14 [2] e7 18 [2] eb 12 [2] fc 19 [2] e7 57 [2] da }

  condition:
    any of them
}