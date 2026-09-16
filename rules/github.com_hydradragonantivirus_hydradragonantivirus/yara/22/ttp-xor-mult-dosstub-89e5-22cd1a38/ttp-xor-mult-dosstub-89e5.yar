rule TTP_XOR_MULT_DOSStub_89e5 {
  strings:
    $key_89e5 = { dd 8d [2] a9 95 [2] ee 97 [2] a9 86 [2] e7 8a [2] eb 80 [2] fc 8b [2] e7 c5 [2] da }

  condition:
    any of them
}