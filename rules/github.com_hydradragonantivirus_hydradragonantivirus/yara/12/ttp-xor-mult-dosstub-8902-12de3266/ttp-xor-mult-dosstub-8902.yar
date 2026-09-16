rule TTP_XOR_MULT_DOSStub_8902 {
  strings:
    $key_8902 = { dd 6a [2] a9 72 [2] ee 70 [2] a9 61 [2] e7 6d [2] eb 67 [2] fc 6c [2] e7 22 [2] da }

  condition:
    any of them
}