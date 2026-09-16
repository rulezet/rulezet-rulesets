rule TTP_XOR_MULT_DOSStub_89e7 {
  strings:
    $key_89e7 = { dd 8f [2] a9 97 [2] ee 95 [2] a9 84 [2] e7 88 [2] eb 82 [2] fc 89 [2] e7 c7 [2] da }

  condition:
    any of them
}