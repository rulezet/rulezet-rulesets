rule TTP_XOR_MULT_DOSStub_8ced {
  strings:
    $key_8ced = { d8 85 [2] ac 9d [2] eb 9f [2] ac 8e [2] e2 82 [2] ee 88 [2] f9 83 [2] e2 cd [2] df }

  condition:
    any of them
}