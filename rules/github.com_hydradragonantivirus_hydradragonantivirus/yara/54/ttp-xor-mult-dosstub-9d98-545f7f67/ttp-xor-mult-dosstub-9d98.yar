rule TTP_XOR_MULT_DOSStub_9d98 {
  strings:
    $key_9d98 = { c9 f0 [2] bd e8 [2] fa ea [2] bd fb [2] f3 f7 [2] ff fd [2] e8 f6 [2] f3 b8 [2] ce }

  condition:
    any of them
}