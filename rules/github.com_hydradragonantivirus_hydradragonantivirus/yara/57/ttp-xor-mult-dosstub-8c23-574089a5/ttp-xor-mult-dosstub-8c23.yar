rule TTP_XOR_MULT_DOSStub_8c23 {
  strings:
    $key_8c23 = { d8 4b [2] ac 53 [2] eb 51 [2] ac 40 [2] e2 4c [2] ee 46 [2] f9 4d [2] e2 03 [2] df }

  condition:
    any of them
}