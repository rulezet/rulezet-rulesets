rule TTP_XOR_MULT_DOSStub_89e0 {
  strings:
    $key_89e0 = { dd 88 [2] a9 90 [2] ee 92 [2] a9 83 [2] e7 8f [2] eb 85 [2] fc 8e [2] e7 c0 [2] da }

  condition:
    any of them
}