rule TTP_XOR_MULT_DOSStub_8903 {
  strings:
    $key_8903 = { dd 6b [2] a9 73 [2] ee 71 [2] a9 60 [2] e7 6c [2] eb 66 [2] fc 6d [2] e7 23 [2] da }

  condition:
    any of them
}