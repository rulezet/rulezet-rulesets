rule TTP_XOR_MULT_DOSStub_9dc1 {
  strings:
    $key_9dc1 = { c9 a9 [2] bd b1 [2] fa b3 [2] bd a2 [2] f3 ae [2] ff a4 [2] e8 af [2] f3 e1 [2] ce }

  condition:
    any of them
}