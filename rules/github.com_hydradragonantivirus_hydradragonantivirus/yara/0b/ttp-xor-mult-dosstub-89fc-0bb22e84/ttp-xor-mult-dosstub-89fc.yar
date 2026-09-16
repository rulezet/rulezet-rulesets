rule TTP_XOR_MULT_DOSStub_89fc {
  strings:
    $key_89fc = { dd 94 [2] a9 8c [2] ee 8e [2] a9 9f [2] e7 93 [2] eb 99 [2] fc 92 [2] e7 dc [2] da }

  condition:
    any of them
}