rule TTP_XOR_MULT_DOSStub_8974 {
  strings:
    $key_8974 = { dd 1c [2] a9 04 [2] ee 06 [2] a9 17 [2] e7 1b [2] eb 11 [2] fc 1a [2] e7 54 [2] da }

  condition:
    any of them
}