rule TTP_XOR_MULT_DOSStub_89e1 {
  strings:
    $key_89e1 = { dd 89 [2] a9 91 [2] ee 93 [2] a9 82 [2] e7 8e [2] eb 84 [2] fc 8f [2] e7 c1 [2] da }

  condition:
    any of them
}