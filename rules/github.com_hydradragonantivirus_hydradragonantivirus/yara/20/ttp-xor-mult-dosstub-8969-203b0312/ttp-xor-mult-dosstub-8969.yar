rule TTP_XOR_MULT_DOSStub_8969 {
  strings:
    $key_8969 = { dd 01 [2] a9 19 [2] ee 1b [2] a9 0a [2] e7 06 [2] eb 0c [2] fc 07 [2] e7 49 [2] da }

  condition:
    any of them
}