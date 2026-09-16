rule TTP_XOR_MULT_DOSStub_8c1d {
  strings:
    $key_8c1d = { d8 75 [2] ac 6d [2] eb 6f [2] ac 7e [2] e2 72 [2] ee 78 [2] f9 73 [2] e2 3d [2] df }

  condition:
    any of them
}