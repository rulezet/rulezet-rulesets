rule TTP_XOR_MULT_DOSStub_894d {
  strings:
    $key_894d = { dd 25 [2] a9 3d [2] ee 3f [2] a9 2e [2] e7 22 [2] eb 28 [2] fc 23 [2] e7 6d [2] da }

  condition:
    any of them
}