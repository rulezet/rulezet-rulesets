rule TTP_XOR_MULT_DOSStub_8911 {
  strings:
    $key_8911 = { dd 79 [2] a9 61 [2] ee 63 [2] a9 72 [2] e7 7e [2] eb 74 [2] fc 7f [2] e7 31 [2] da }

  condition:
    any of them
}