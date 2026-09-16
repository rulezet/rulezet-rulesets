rule TTP_XOR_MULT_DOSStub_892f {
  strings:
    $key_892f = { dd 47 [2] a9 5f [2] ee 5d [2] a9 4c [2] e7 40 [2] eb 4a [2] fc 41 [2] e7 0f [2] da }

  condition:
    any of them
}