rule TTP_XOR_MULT_DOSStub_8958 {
  strings:
    $key_8958 = { dd 30 [2] a9 28 [2] ee 2a [2] a9 3b [2] e7 37 [2] eb 3d [2] fc 36 [2] e7 78 [2] da }

  condition:
    any of them
}