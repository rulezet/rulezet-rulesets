rule TTP_XOR_MULT_DOSStub_9dd2 {
  strings:
    $key_9dd2 = { c9 ba [2] bd a2 [2] fa a0 [2] bd b1 [2] f3 bd [2] ff b7 [2] e8 bc [2] f3 f2 [2] ce }

  condition:
    any of them
}