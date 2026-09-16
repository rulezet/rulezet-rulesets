rule TTP_XOR_MULT_DOSStub_897a {
  strings:
    $key_897a = { dd 12 [2] a9 0a [2] ee 08 [2] a9 19 [2] e7 15 [2] eb 1f [2] fc 14 [2] e7 5a [2] da }

  condition:
    any of them
}