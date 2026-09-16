rule TTP_XOR_MULT_DOSStub_8914 {
  strings:
    $key_8914 = { dd 7c [2] a9 64 [2] ee 66 [2] a9 77 [2] e7 7b [2] eb 71 [2] fc 7a [2] e7 34 [2] da }

  condition:
    any of them
}