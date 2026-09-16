rule TTP_XOR_MULT_DOSStub_8cd3 {
  strings:
    $key_8cd3 = { d8 bb [2] ac a3 [2] eb a1 [2] ac b0 [2] e2 bc [2] ee b6 [2] f9 bd [2] e2 f3 [2] df }

  condition:
    any of them
}