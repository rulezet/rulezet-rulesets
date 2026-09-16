rule TTP_XOR_MULT_DOSStub_89eb {
  strings:
    $key_89eb = { dd 83 [2] a9 9b [2] ee 99 [2] a9 88 [2] e7 84 [2] eb 8e [2] fc 85 [2] e7 cb [2] da }

  condition:
    any of them
}