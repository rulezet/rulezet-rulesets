rule TTP_XOR_MULT_DOSStub_8cd4 {
  strings:
    $key_8cd4 = { d8 bc [2] ac a4 [2] eb a6 [2] ac b7 [2] e2 bb [2] ee b1 [2] f9 ba [2] e2 f4 [2] df }

  condition:
    any of them
}