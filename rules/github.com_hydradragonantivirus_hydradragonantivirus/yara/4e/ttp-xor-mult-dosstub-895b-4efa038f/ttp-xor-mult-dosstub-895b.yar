rule TTP_XOR_MULT_DOSStub_895b {
  strings:
    $key_895b = { dd 33 [2] a9 2b [2] ee 29 [2] a9 38 [2] e7 34 [2] eb 3e [2] fc 35 [2] e7 7b [2] da }

  condition:
    any of them
}