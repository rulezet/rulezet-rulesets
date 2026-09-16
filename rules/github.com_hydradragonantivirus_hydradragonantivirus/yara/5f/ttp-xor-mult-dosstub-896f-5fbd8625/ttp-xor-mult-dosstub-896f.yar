rule TTP_XOR_MULT_DOSStub_896f {
  strings:
    $key_896f = { dd 07 [2] a9 1f [2] ee 1d [2] a9 0c [2] e7 00 [2] eb 0a [2] fc 01 [2] e7 4f [2] da }

  condition:
    any of them
}