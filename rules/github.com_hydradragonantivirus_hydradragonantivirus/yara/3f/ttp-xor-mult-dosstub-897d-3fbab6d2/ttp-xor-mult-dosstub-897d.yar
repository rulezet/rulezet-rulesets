rule TTP_XOR_MULT_DOSStub_897d {
  strings:
    $key_897d = { dd 15 [2] a9 0d [2] ee 0f [2] a9 1e [2] e7 12 [2] eb 18 [2] fc 13 [2] e7 5d [2] da }

  condition:
    any of them
}