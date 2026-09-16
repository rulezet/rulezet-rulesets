rule TTP_XOR_MULT_DOSStub_8ca3 {
  strings:
    $key_8ca3 = { d8 cb [2] ac d3 [2] eb d1 [2] ac c0 [2] e2 cc [2] ee c6 [2] f9 cd [2] e2 83 [2] df }

  condition:
    any of them
}