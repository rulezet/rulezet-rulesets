rule TTP_XOR_MULT_DOSStub_8c6b {
  strings:
    $key_8c6b = { d8 03 [2] ac 1b [2] eb 19 [2] ac 08 [2] e2 04 [2] ee 0e [2] f9 05 [2] e2 4b [2] df }

  condition:
    any of them
}