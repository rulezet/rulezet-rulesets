rule TTP_XOR_MULT_DOSStub_8c55 {
  strings:
    $key_8c55 = { d8 3d [2] ac 25 [2] eb 27 [2] ac 36 [2] e2 3a [2] ee 30 [2] f9 3b [2] e2 75 [2] df }

  condition:
    any of them
}