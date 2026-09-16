rule TTP_XOR_MULT_DOSStub_892b {
  strings:
    $key_892b = { dd 43 [2] a9 5b [2] ee 59 [2] a9 48 [2] e7 44 [2] eb 4e [2] fc 45 [2] e7 0b [2] da }

  condition:
    any of them
}