rule TTP_XOR_MULT_DOSStub_8932 {
  strings:
    $key_8932 = { dd 5a [2] a9 42 [2] ee 40 [2] a9 51 [2] e7 5d [2] eb 57 [2] fc 5c [2] e7 12 [2] da }

  condition:
    any of them
}