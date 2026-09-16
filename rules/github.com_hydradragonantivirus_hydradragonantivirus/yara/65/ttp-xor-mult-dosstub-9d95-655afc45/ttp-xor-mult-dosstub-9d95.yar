rule TTP_XOR_MULT_DOSStub_9d95 {
  strings:
    $key_9d95 = { c9 fd [2] bd e5 [2] fa e7 [2] bd f6 [2] f3 fa [2] ff f0 [2] e8 fb [2] f3 b5 [2] ce }

  condition:
    any of them
}