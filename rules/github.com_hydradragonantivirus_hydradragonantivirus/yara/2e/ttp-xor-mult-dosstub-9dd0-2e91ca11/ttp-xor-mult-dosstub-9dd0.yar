rule TTP_XOR_MULT_DOSStub_9dd0 {
  strings:
    $key_9dd0 = { c9 b8 [2] bd a0 [2] fa a2 [2] bd b3 [2] f3 bf [2] ff b5 [2] e8 be [2] f3 f0 [2] ce }

  condition:
    any of them
}