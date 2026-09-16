rule TTP_XOR_MULT_DOSStub_890f {
  strings:
    $key_890f = { dd 67 [2] a9 7f [2] ee 7d [2] a9 6c [2] e7 60 [2] eb 6a [2] fc 61 [2] e7 2f [2] da }

  condition:
    any of them
}