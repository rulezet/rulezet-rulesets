rule TTP_XOR_MULT_DOSStub_8c52 {
  strings:
    $key_8c52 = { d8 3a [2] ac 22 [2] eb 20 [2] ac 31 [2] e2 3d [2] ee 37 [2] f9 3c [2] e2 72 [2] df }

  condition:
    any of them
}