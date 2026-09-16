rule TTP_XOR_MULT_DOSStub_8c0c {
  strings:
    $key_8c0c = { d8 64 [2] ac 7c [2] eb 7e [2] ac 6f [2] e2 63 [2] ee 69 [2] f9 62 [2] e2 2c [2] df }

  condition:
    any of them
}