rule TTP_XOR_MULT_DOSStub_9d92 {
  strings:
    $key_9d92 = { c9 fa [2] bd e2 [2] fa e0 [2] bd f1 [2] f3 fd [2] ff f7 [2] e8 fc [2] f3 b2 [2] ce }

  condition:
    any of them
}