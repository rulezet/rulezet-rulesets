rule TTP_XOR_MULT_DOSStub_8c01 {
  strings:
    $key_8c01 = { d8 69 [2] ac 71 [2] eb 73 [2] ac 62 [2] e2 6e [2] ee 64 [2] f9 6f [2] e2 21 [2] df }

  condition:
    any of them
}