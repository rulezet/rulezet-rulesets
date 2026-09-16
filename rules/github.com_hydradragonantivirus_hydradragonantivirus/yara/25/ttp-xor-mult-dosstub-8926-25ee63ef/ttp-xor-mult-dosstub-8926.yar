rule TTP_XOR_MULT_DOSStub_8926 {
  strings:
    $key_8926 = { dd 4e [2] a9 56 [2] ee 54 [2] a9 45 [2] e7 49 [2] eb 43 [2] fc 48 [2] e7 06 [2] da }

  condition:
    any of them
}