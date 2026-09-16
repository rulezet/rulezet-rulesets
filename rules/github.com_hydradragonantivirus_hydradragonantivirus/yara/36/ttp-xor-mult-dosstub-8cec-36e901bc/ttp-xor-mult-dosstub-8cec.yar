rule TTP_XOR_MULT_DOSStub_8cec {
  strings:
    $key_8cec = { d8 84 [2] ac 9c [2] eb 9e [2] ac 8f [2] e2 83 [2] ee 89 [2] f9 82 [2] e2 cc [2] df }

  condition:
    any of them
}