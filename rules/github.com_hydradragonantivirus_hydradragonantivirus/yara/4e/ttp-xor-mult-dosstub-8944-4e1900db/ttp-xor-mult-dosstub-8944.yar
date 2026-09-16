rule TTP_XOR_MULT_DOSStub_8944 {
  strings:
    $key_8944 = { dd 2c [2] a9 34 [2] ee 36 [2] a9 27 [2] e7 2b [2] eb 21 [2] fc 2a [2] e7 64 [2] da }

  condition:
    any of them
}