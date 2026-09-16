rule TTP_XOR_MULT_DOSStub_9d96 {
  strings:
    $key_9d96 = { c9 fe [2] bd e6 [2] fa e4 [2] bd f5 [2] f3 f9 [2] ff f3 [2] e8 f8 [2] f3 b6 [2] ce }

  condition:
    any of them
}