rule TTP_XOR_MULT_DOSStub_893e {
  strings:
    $key_893e = { dd 56 [2] a9 4e [2] ee 4c [2] a9 5d [2] e7 51 [2] eb 5b [2] fc 50 [2] e7 1e [2] da }

  condition:
    any of them
}