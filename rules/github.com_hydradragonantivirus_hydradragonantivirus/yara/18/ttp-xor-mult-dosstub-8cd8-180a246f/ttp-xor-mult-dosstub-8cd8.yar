rule TTP_XOR_MULT_DOSStub_8cd8 {
  strings:
    $key_8cd8 = { d8 b0 [2] ac a8 [2] eb aa [2] ac bb [2] e2 b7 [2] ee bd [2] f9 b6 [2] e2 f8 [2] df }

  condition:
    any of them
}