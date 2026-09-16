rule TTP_XOR_MULT_DOSStub_890e {
  strings:
    $key_890e = { dd 66 [2] a9 7e [2] ee 7c [2] a9 6d [2] e7 61 [2] eb 6b [2] fc 60 [2] e7 2e [2] da }

  condition:
    any of them
}