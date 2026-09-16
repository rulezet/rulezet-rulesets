rule TTP_XOR_MULT_DOSStub_8965 {
  strings:
    $key_8965 = { dd 0d [2] a9 15 [2] ee 17 [2] a9 06 [2] e7 0a [2] eb 00 [2] fc 0b [2] e7 45 [2] da }

  condition:
    any of them
}