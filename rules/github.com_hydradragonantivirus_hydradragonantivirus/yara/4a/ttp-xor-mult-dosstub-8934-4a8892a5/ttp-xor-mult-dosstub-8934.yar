rule TTP_XOR_MULT_DOSStub_8934 {
  strings:
    $key_8934 = { dd 5c [2] a9 44 [2] ee 46 [2] a9 57 [2] e7 5b [2] eb 51 [2] fc 5a [2] e7 14 [2] da }

  condition:
    any of them
}