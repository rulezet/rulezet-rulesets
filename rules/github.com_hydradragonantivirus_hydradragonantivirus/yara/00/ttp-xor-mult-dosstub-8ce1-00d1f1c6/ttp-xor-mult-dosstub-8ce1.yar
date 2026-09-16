rule TTP_XOR_MULT_DOSStub_8ce1 {
  strings:
    $key_8ce1 = { d8 89 [2] ac 91 [2] eb 93 [2] ac 82 [2] e2 8e [2] ee 84 [2] f9 8f [2] e2 c1 [2] df }

  condition:
    any of them
}