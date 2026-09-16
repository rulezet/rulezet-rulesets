rule TTP_XOR_MULT_DOSStub_8943 {
  strings:
    $key_8943 = { dd 2b [2] a9 33 [2] ee 31 [2] a9 20 [2] e7 2c [2] eb 26 [2] fc 2d [2] e7 63 [2] da }

  condition:
    any of them
}