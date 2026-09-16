rule TTP_XOR_MULT_DOSStub_890a {
  strings:
    $key_890a = { dd 62 [2] a9 7a [2] ee 78 [2] a9 69 [2] e7 65 [2] eb 6f [2] fc 64 [2] e7 2a [2] da }

  condition:
    any of them
}