rule TTP_XOR_MULT_DOSStub_892a {
  strings:
    $key_892a = { dd 42 [2] a9 5a [2] ee 58 [2] a9 49 [2] e7 45 [2] eb 4f [2] fc 44 [2] e7 0a [2] da }

  condition:
    any of them
}