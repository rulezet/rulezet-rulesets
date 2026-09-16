rule TTP_XOR_MULT_DOSStub_8939 {
  strings:
    $key_8939 = { dd 51 [2] a9 49 [2] ee 4b [2] a9 5a [2] e7 56 [2] eb 5c [2] fc 57 [2] e7 19 [2] da }

  condition:
    any of them
}