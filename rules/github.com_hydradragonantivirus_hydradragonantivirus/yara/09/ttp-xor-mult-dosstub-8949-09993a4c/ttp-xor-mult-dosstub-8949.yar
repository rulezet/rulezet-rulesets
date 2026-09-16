rule TTP_XOR_MULT_DOSStub_8949 {
  strings:
    $key_8949 = { dd 21 [2] a9 39 [2] ee 3b [2] a9 2a [2] e7 26 [2] eb 2c [2] fc 27 [2] e7 69 [2] da }

  condition:
    any of them
}