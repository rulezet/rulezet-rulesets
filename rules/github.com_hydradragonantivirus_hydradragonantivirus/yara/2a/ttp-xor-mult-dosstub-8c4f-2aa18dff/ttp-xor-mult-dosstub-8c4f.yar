rule TTP_XOR_MULT_DOSStub_8c4f {
  strings:
    $key_8c4f = { d8 27 [2] ac 3f [2] eb 3d [2] ac 2c [2] e2 20 [2] ee 2a [2] f9 21 [2] e2 6f [2] df }

  condition:
    any of them
}