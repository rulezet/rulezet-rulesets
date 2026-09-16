rule TTP_XOR_MULT_DOSStub_8c3d {
  strings:
    $key_8c3d = { d8 55 [2] ac 4d [2] eb 4f [2] ac 5e [2] e2 52 [2] ee 58 [2] f9 53 [2] e2 1d [2] df }

  condition:
    any of them
}