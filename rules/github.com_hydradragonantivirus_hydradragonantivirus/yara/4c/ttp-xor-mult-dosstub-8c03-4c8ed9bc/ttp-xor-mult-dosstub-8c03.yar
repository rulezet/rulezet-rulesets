rule TTP_XOR_MULT_DOSStub_8c03 {
  strings:
    $key_8c03 = { d8 6b [2] ac 73 [2] eb 71 [2] ac 60 [2] e2 6c [2] ee 66 [2] f9 6d [2] e2 23 [2] df }

  condition:
    any of them
}