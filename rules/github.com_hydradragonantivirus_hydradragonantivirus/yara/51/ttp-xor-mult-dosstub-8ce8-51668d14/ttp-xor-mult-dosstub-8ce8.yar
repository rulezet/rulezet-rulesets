rule TTP_XOR_MULT_DOSStub_8ce8 {
  strings:
    $key_8ce8 = { d8 80 [2] ac 98 [2] eb 9a [2] ac 8b [2] e2 87 [2] ee 8d [2] f9 86 [2] e2 c8 [2] df }

  condition:
    any of them
}