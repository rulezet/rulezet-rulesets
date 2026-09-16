rule TTP_XOR_MULT_DOSStub_892d {
  strings:
    $key_892d = { dd 45 [2] a9 5d [2] ee 5f [2] a9 4e [2] e7 42 [2] eb 48 [2] fc 43 [2] e7 0d [2] da }

  condition:
    any of them
}