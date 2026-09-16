rule TTP_XOR_MULT_DOSStub_8cfb {
  strings:
    $key_8cfb = { d8 93 [2] ac 8b [2] eb 89 [2] ac 98 [2] e2 94 [2] ee 9e [2] f9 95 [2] e2 db [2] df }

  condition:
    any of them
}