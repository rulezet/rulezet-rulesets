rule TTP_XOR_MULT_DOSStub_8973 {
  strings:
    $key_8973 = { dd 1b [2] a9 03 [2] ee 01 [2] a9 10 [2] e7 1c [2] eb 16 [2] fc 1d [2] e7 53 [2] da }

  condition:
    any of them
}