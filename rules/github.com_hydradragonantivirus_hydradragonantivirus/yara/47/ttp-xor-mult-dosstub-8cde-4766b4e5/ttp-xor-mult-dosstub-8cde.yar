rule TTP_XOR_MULT_DOSStub_8cde {
  strings:
    $key_8cde = { d8 b6 [2] ac ae [2] eb ac [2] ac bd [2] e2 b1 [2] ee bb [2] f9 b0 [2] e2 fe [2] df }

  condition:
    any of them
}