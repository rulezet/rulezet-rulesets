rule TTP_XOR_MULT_DOSStub_897e {
  strings:
    $key_897e = { dd 16 [2] a9 0e [2] ee 0c [2] a9 1d [2] e7 11 [2] eb 1b [2] fc 10 [2] e7 5e [2] da }

  condition:
    any of them
}