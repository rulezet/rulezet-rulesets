rule TTP_XOR_MULT_DOSStub_9d97 {
  strings:
    $key_9d97 = { c9 ff [2] bd e7 [2] fa e5 [2] bd f4 [2] f3 f8 [2] ff f2 [2] e8 f9 [2] f3 b7 [2] ce }

  condition:
    any of them
}