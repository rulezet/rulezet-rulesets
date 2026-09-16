rule TTP_XOR_MULT_DOSStub_8c6c {
  strings:
    $key_8c6c = { d8 04 [2] ac 1c [2] eb 1e [2] ac 0f [2] e2 03 [2] ee 09 [2] f9 02 [2] e2 4c [2] df }

  condition:
    any of them
}