rule TTP_XOR_MULT_DOSStub_893f {
  strings:
    $key_893f = { dd 57 [2] a9 4f [2] ee 4d [2] a9 5c [2] e7 50 [2] eb 5a [2] fc 51 [2] e7 1f [2] da }

  condition:
    any of them
}