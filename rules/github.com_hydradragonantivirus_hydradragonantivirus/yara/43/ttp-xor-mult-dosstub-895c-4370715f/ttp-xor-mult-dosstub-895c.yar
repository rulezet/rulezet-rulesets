rule TTP_XOR_MULT_DOSStub_895c {
  strings:
    $key_895c = { dd 34 [2] a9 2c [2] ee 2e [2] a9 3f [2] e7 33 [2] eb 39 [2] fc 32 [2] e7 7c [2] da }

  condition:
    any of them
}