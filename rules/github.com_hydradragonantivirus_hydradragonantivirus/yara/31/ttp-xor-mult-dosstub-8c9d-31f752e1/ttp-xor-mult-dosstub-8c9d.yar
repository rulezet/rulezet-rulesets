rule TTP_XOR_MULT_DOSStub_8c9d {
  strings:
    $key_8c9d = { d8 f5 [2] ac ed [2] eb ef [2] ac fe [2] e2 f2 [2] ee f8 [2] f9 f3 [2] e2 bd [2] df }

  condition:
    any of them
}