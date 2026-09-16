rule TTP_XOR_MULT_DOSStub_8964 {
  strings:
    $key_8964 = { dd 0c [2] a9 14 [2] ee 16 [2] a9 07 [2] e7 0b [2] eb 01 [2] fc 0a [2] e7 44 [2] da }

  condition:
    any of them
}