rule TTP_XOR_MULT_DOSStub_8c28 {
  strings:
    $key_8c28 = { d8 40 [2] ac 58 [2] eb 5a [2] ac 4b [2] e2 47 [2] ee 4d [2] f9 46 [2] e2 08 [2] df }

  condition:
    any of them
}