rule TTP_XOR_MULT_DOSStub_892c {
  strings:
    $key_892c = { dd 44 [2] a9 5c [2] ee 5e [2] a9 4f [2] e7 43 [2] eb 49 [2] fc 42 [2] e7 0c [2] da }

  condition:
    any of them
}