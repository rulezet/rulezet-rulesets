rule TTP_XOR_MULT_DOSStub_9dd1 {
  strings:
    $key_9dd1 = { c9 b9 [2] bd a1 [2] fa a3 [2] bd b2 [2] f3 be [2] ff b4 [2] e8 bf [2] f3 f1 [2] ce }

  condition:
    any of them
}