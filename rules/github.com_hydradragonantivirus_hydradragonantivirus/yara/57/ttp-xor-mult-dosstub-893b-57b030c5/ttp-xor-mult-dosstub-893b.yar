rule TTP_XOR_MULT_DOSStub_893b {
  strings:
    $key_893b = { dd 53 [2] a9 4b [2] ee 49 [2] a9 58 [2] e7 54 [2] eb 5e [2] fc 55 [2] e7 1b [2] da }

  condition:
    any of them
}