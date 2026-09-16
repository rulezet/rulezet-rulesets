rule TTP_XOR_MULT_DOSStub_8948 {
  strings:
    $key_8948 = { dd 20 [2] a9 38 [2] ee 3a [2] a9 2b [2] e7 27 [2] eb 2d [2] fc 26 [2] e7 68 [2] da }

  condition:
    any of them
}